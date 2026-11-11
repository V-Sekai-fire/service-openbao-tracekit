package e2e

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/proxy"
)

// refDir finds a Tracekit v1.4.2 checkout to import the real client from.
// Nothing is installed: the client runs from the checkout with system python3.
func refDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv("TRACEKIT_REF")
	if d == "" {
		home, _ := os.UserHomeDir()
		d = filepath.Join(home, ".hermes", "cache", "scratch", "Tracekit-ref")
	}
	if _, err := os.Stat(filepath.Join(d, "tracekit", "sdk", "client.py")); err != nil {
		t.Skip("no Tracekit v1.4.2 checkout (set TRACEKIT_REF): the real client is not measured")
	}
	return d
}

// The real v1.4.2 client, unmodified, through the proxy and real Bao: hello, register_run,
// decide, complete and close_run all succeed, and the default policy denies the call.
func TestRealClient(t *testing.T) {
	ref := refDir(t)
	py := os.Getenv("TRACEKIT_PYTHON")
	if py == "" {
		py, _ = exec.LookPath("python3")
	}
	if py == "" {
		t.Skip("python3 not found: the real client is not measured")
	}
	if err := exec.Command(py, "-c", "import rfc8785").Run(); err != nil {
		t.Skipf("%s cannot import rfc8785 (set TRACEKIT_PYTHON): the real client is not measured", py)
	}
	s := start(t)
	tok, _ := s.login(t, "alice")
	px := httptest.NewServer(proxy.New(s.base+"/v1/tracekit/rpc", nil))
	defer px.Close()

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs("client_check.py")
	cmd := exec.Command(py, script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "PYTHONDONTWRITEBYTECODE=1",
		"TRACEKIT_REF=" + ref, "SIGNER_URL=" + px.URL, "SIGNER_TOKEN_FILE=" + tokFile}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("client script: %v\n%s", err, raw)
	}
	var out struct {
		RunID    string   `json:"run_id"`
		Decision string   `json:"decision"`
		Unavail  bool     `json:"unavailable"`
		Complete any      `json:"complete"`
		Closed   bool     `json:"closed"`
		Warnings []string `json:"warnings"`
		Error    string   `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	if out.Error != "" {
		t.Fatalf("client raised: %s", out.Error)
	}
	if out.RunID == "" || out.Decision != "deny" || out.Unavail {
		t.Errorf("run %q decision %q unavailable %v", out.RunID, out.Decision, out.Unavail)
	}
	if out.Complete == nil {
		t.Errorf("complete returned nothing; warnings: %v", out.Warnings)
	}
	if !out.Closed {
		t.Errorf("run not closed; warnings: %v", out.Warnings)
	}
}
