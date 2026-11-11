// Package e2e runs the built plugin inside a throwaway `bao server -dev` and
// measures identity (L3) and authorisation (L2) through the real Bao path.
//
// Safety: the server binds a free loopback port (never 8200), runs with a
// minimal environment and a temp HOME, and every credential below is a fake
// literal that lives only in this process. Nothing is written to a token file.
// Without `bao` on PATH the tests skip, and the harness reports them as not measured.
package e2e

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const rootToken = "test-only-root-token"

type srv struct {
	base string
	c    *http.Client
}

func start(t *testing.T) *srv {
	t.Helper()
	bao, err := exec.LookPath("bao")
	if err != nil {
		t.Skip("bao is not on PATH: L2 and L3 are not measured")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir()) // Bao refuses a symlinked plugin directory
	if err != nil {
		t.Fatal(err)
	}
	plugins := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(plugins, "service-openbao-tracekit")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/service-openbao-tracekit").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if port == 8200 {
		t.Fatal("refusing to use the live vault port")
	}
	cfg := filepath.Join(dir, "bao.hcl")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("plugin_directory = %q\ndisable_mlock = true\n", plugins)), 0o600); err != nil {
		t.Fatal(err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bao, "server", "-dev",
		fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", port),
		"-dev-root-token-id="+rootToken, "-dev-no-store-token", "-config="+cfg)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		var once sync.Once
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "Root Token:") {
				once.Do(func() { close(ready) })
			}
		}
	}()
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Signal(os.Interrupt); <-done; pr.Close() })
	select {
	case <-ready:
	case <-done:
		t.Fatal("bao exited before it was ready")
	}

	s := &srv{base: fmt.Sprintf("http://127.0.0.1:%d", port), c: &http.Client{Transport: &http.Transport{Proxy: nil}}}
	must := func(method, path string, body any) {
		t.Helper()
		if st, m := s.do(t, method, path, rootToken, body); st >= 300 {
			t.Fatalf("%s %s: %d %v", method, path, st, m)
		}
	}
	must("PUT", "/v1/sys/plugins/catalog/secret/service-openbao-tracekit",
		map[string]any{"sha256": hex.EncodeToString(sum[:]), "command": "service-openbao-tracekit"})
	must("POST", "/v1/sys/mounts/tracekit", map[string]any{"type": "service-openbao-tracekit"})
	must("POST", "/v1/sys/auth/userpass", map[string]any{"type": "userpass"})
	must("PUT", "/v1/sys/policies/acl/agent",
		map[string]any{"policy": `path "tracekit/rpc" { capabilities = ["update"] }`})
	for _, u := range []string{"alice", "bob"} {
		must("POST", "/v1/auth/userpass/users/"+u, map[string]any{
			"password": u + "-test-pw", "token_policies": []string{"agent"}, "token_no_default_policy": true})
	}
	return s
}

func (s *srv) do(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// login returns a fresh client token and the entity id Bao attached to it.
func (s *srv) login(t *testing.T, user string) (token, entity string) {
	t.Helper()
	st, m := s.do(t, "POST", "/v1/auth/userpass/login/"+user, "", map[string]any{"password": user + "-test-pw"})
	auth, _ := m["auth"].(map[string]any)
	if st != 200 || auth == nil {
		t.Fatalf("login %s: %d %v", user, st, m)
	}
	token, _ = auth["client_token"].(string)
	entity, _ = auth["entity_id"].(string)
	return token, entity
}

// rpc sends one frame the way the proxy does, with a Bearer token.
func (s *srv) rpc(t *testing.T, token, frame string) map[string]any {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"frame": frame})
	req, _ := http.NewRequest("POST", s.base+"/v1/tracekit/rpc", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("reply is not JSON (%d): %s", resp.StatusCode, out)
	}
	return m
}

func code(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func register(t *testing.T, s *srv, token, reqID, extra string) map[string]any {
	t.Helper()
	return s.rpc(t, token, `{"method":"register_run","request_id":"`+reqID+`","agent":"hermes"`+extra+`}`)
}

func decide(t *testing.T, s *srv, token, reqID, runID, runTok, call string) map[string]any {
	t.Helper()
	return s.rpc(t, token, `{"method":"decide","request_id":"`+reqID+`","run_id":"`+runID+`","run_token":"`+runTok+
		`","stream":"s","client_seq":0,"tool_call_id":"`+call+`","tool":"bash","args_source":"raw","args":"{}"}`)
}

func TestIdentityAndScope(t *testing.T) {
	s := start(t)
	alice1, aliceEntity := s.login(t, "alice")
	_, bobEntity := s.login(t, "bob")
	bob, _ := s.login(t, "bob")

	t.Run("entity arrives and a run can be registered", func(t *testing.T) {
		if aliceEntity == "" || bobEntity == "" {
			t.Fatalf("login gave no entity id: %q %q", aliceEntity, bobEntity)
		}
		if aliceEntity == bobEntity {
			t.Fatal("two principals share one entity")
		}
		m := register(t, s, alice1, "arrive-1", "")
		if code(m) != "" || m["run_id"] == nil {
			t.Fatalf("register_run refused: %v", m)
		}
	})

	t.Run("identity survives token rotation", func(t *testing.T) {
		m := register(t, s, alice1, "rot-1", "")
		runID, runTok := m["run_id"].(string), m["run_token"].(string)
		alice2, entity2 := s.login(t, "alice")
		if alice2 == alice1 || entity2 != aliceEntity {
			t.Fatalf("second login: same token %v, entity %q want %q", alice2 == alice1, entity2, aliceEntity)
		}
		d := decide(t, s, alice2, "rot-2", runID, runTok, "c1")
		if code(d) != "" || d["decision"] != "deny" {
			t.Fatalf("rotated token not accepted: %v", d)
		}
	})

	t.Run("another principal cannot use the run", func(t *testing.T) {
		m := register(t, s, alice1, "iso-1", "")
		d := decide(t, s, bob, "iso-2", m["run_id"].(string), m["run_token"].(string), "c1")
		if code(d) != "run_token_invalid" {
			t.Fatalf("bob used alice's run: %v", d)
		}
	})

	t.Run("tokens without an entity are refused", func(t *testing.T) {
		if c := code(register(t, s, rootToken, "ent-1", "")); c != "unauthenticated" {
			t.Errorf("root token: %q", c)
		}
		st, m := s.do(t, "POST", "/v1/auth/token/create", rootToken,
			map[string]any{"policies": []string{"agent"}, "no_default_policy": true})
		auth, _ := m["auth"].(map[string]any)
		if st != 200 || auth == nil {
			t.Fatalf("token create: %d %v", st, m)
		}
		plain, _ := auth["client_token"].(string)
		if c := code(register(t, s, plain, "ent-2", "")); c != "unauthenticated" {
			t.Errorf("plain token: %q", c)
		}
	})

	t.Run("a frame cannot name its own identity", func(t *testing.T) {
		for i, extra := range []string{
			`,"caller":"gateway:x"`, `,"principal":"person:eve"`, `,"principal_token":"abc"`,
		} {
			m := register(t, s, alice1, fmt.Sprintf("spoof-%d", i), extra)
			if code(m) == "" || m["run_id"] != nil {
				t.Errorf("accepted %s: %v", extra, m)
			}
		}
	})

	t.Run("the scoped token reaches nothing else", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{"GET", "/v1/sys/mounts"},
			{"POST", "/v1/auth/token/create"},
			{"GET", "/v1/sys/plugins/catalog"},
			{"POST", "/v1/tracekit/other"},
			{"GET", "/v1/tracekit/trust"},
			{"GET", "/v1/tracekit/runs/default/x/export"},
			{"POST", "/v1/sys/seal"},
		} {
			if st, _ := s.do(t, c.method, c.path, alice1, map[string]any{}); st != 403 && st != 404 {
				t.Errorf("%s %s: %d", c.method, c.path, st)
			}
		}
	})
}
