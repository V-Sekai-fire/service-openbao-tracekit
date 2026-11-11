package e2e

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/proxy"
)

// The real v1.4.2 client, unmodified, with an operator-stored allow for bash:
// decide allows, approval_consume answers ok, complete succeeds, and the client
// raised and warned about nothing. The client swallows errors into warnings, so
// the warnings list must be empty for the test to pass.
func TestRealClientAllow(t *testing.T) {
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
	if st, m := s.do(t, "POST", "/v1/tracekit/policy", rootToken, map[string]any{"allow": []string{"bash"}}); st >= 300 {
		t.Fatalf("operator policy write: %d %v", st, m)
	}
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
		"TRACEKIT_REF=" + ref, "SIGNER_URL=" + px.URL, "SIGNER_TOKEN_FILE=" + tokFile, "CHECK_MODE=allow"}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("client script: %v\n%s", err, raw)
	}
	var out struct {
		Decision string         `json:"decision"`
		Unavail  bool           `json:"unavailable"`
		Consume  map[string]any `json:"consume"`
		Complete any            `json:"complete"`
		Closed   bool           `json:"closed"`
		Warnings []string       `json:"warnings"`
		Error    string         `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	if out.Error != "" {
		t.Fatalf("client raised: %s", out.Error)
	}
	if out.Decision != "allow" || out.Unavail {
		t.Errorf("decision %q unavailable %v, want allow", out.Decision, out.Unavail)
	}
	if ok, _ := out.Consume["ok"].(bool); !ok {
		t.Errorf("approval_consume: %v", out.Consume)
	}
	if out.Complete == nil {
		t.Errorf("complete returned nothing; warnings: %v", out.Warnings)
	}
	if !out.Closed {
		t.Errorf("run not closed; warnings: %v", out.Warnings)
	}
	if len(out.Warnings) != 0 {
		t.Errorf("client warned: %v", out.Warnings)
	}
}
