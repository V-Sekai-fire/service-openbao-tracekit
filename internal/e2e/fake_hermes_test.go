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

// A fake Hermes agent (no LLM) drives the unmodified v1.4.2 client through the Hermes hook
// surface, then checks engine behaviour the hooks do not reach. Assertions are on behaviour
// only: no storage keys, so the test survives the state moves planned for step b.
func TestFakeHermesAgent(t *testing.T) {
	ref := refDir(t)
	py := os.Getenv("TRACEKIT_PYTHON")
	if py == "" {
		py, _ = exec.LookPath("python3")
	}
	if py == "" {
		t.Skip("python3 not found: the fake Hermes agent is not measured")
	}
	if err := exec.Command(py, "-c", "import rfc8785").Run(); err != nil {
		t.Skipf("%s cannot import rfc8785 (set TRACEKIT_PYTHON): the fake Hermes agent is not measured", py)
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
	script, _ := filepath.Abs("fake_hermes_agent.py")
	cmd := exec.Command(py, script)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "PYTHONDONTWRITEBYTECODE=1",
		"TRACEKIT_REF=" + ref, "SIGNER_URL=" + px.URL, "SIGNER_TOKEN_FILE=" + tokFile}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("fake agent: %v\n%s", err, raw)
	}
	var out struct {
		Allowed       []string `json:"allowed"`
		Blocked       []string `json:"blocked"`
		DeniedMessage *string  `json:"denied_message"`
		RunID         string   `json:"run_id"`
		ConsumeOK     *bool    `json:"consume_ok"`
		ConsumeReason *string  `json:"consume_reason"`
		Replay        bool     `json:"replay_identical"`
		ConflictCode  *string  `json:"conflict_code"`
		Closed        bool     `json:"closed"`
		Warnings      []string `json:"warnings"`
		Error         string   `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not JSON: %s", raw)
	}
	if out.Error != "" {
		t.Fatalf("fake agent raised: %s", out.Error)
	}
	if out.RunID == "" {
		t.Error("no run was registered")
	}
	// More than the in-flight cap of 8, so the test guards the in-flight choice of step b1.
	if len(out.Allowed) != 9 || len(out.Blocked) != 0 {
		t.Errorf("allowed %d blocked %d, want 9 and 0", len(out.Allowed), len(out.Blocked))
	}
	if out.DeniedMessage == nil {
		t.Error("the call off the allow list was not blocked")
	}
	if out.ConsumeOK == nil || *out.ConsumeOK {
		t.Errorf("approval_consume for an undecided call was not refused: %v", out.ConsumeOK)
	}
	if !out.Replay {
		t.Error("a repeated request_id did not return the identical reply")
	}
	if out.ConflictCode == nil || *out.ConflictCode != "conflict" {
		t.Errorf("reused request_id with another payload: code %v, want conflict", out.ConflictCode)
	}
	if !out.Closed {
		t.Error("run not closed")
	}
	if len(out.Warnings) != 0 {
		t.Errorf("the client warned: %v", out.Warnings)
	}
}
