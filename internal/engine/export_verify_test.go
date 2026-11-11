package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/bundle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/checkpoint"
)

// runVerify runs the upstream verifier on a bundle with trust.json, with PYTHONPATH set to the
// reference checkout and nothing else inherited from the environment.
func runVerify(t *testing.T, ref, py, home, bundlePath, trustPath string) (string, int) {
	t.Helper()
	cmd := exec.Command(py, "-m", "tracekit", "verify", bundlePath, "--trust", trustPath)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PYTHONPATH=" + ref, "PYTHONDONTWRITEBYTECODE=1"}
	out, err := cmd.CombinedOutput()
	rc := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		rc = ee.ExitCode()
	}
	return string(out), rc
}

func hasLine(out, want string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}

func failLines(out string) string {
	var b []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "[FAIL]") || strings.Contains(l, "Integrity:") {
			b = append(b, l)
		}
	}
	return strings.Join(b, "\n")
}

// The export of a closed run verifies upstream, and a copy with one edited record fails at
// that record's seq, with the manifest made consistent so only the chain can fail.
func TestExportVerifiesUpstream(t *testing.T) {
	ref, py := os.Getenv("TRACEKIT_REF"), os.Getenv("TRACEKIT_PYTHON")
	if ref == "" || py == "" {
		t.Skip("TRACEKIT_REF and TRACEKIT_PYTHON are needed: the upstream verifier is not run")
	}
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m := r.call(alice, closeFrame(runID, tok, "c")); code(m) != "" {
		t.Fatalf("close_run refused: %v", m)
	}
	var tenant string
	firstSeq := -1
	for _, en := range entriesOf(t, r.s) {
		if en.RunID == runID && firstSeq < 0 {
			firstSeq, tenant = en.Seq, en.Tenant
		}
	}
	files, err := r.e.Export(context.Background(), r.s, tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	vk, err := checkpoint.VKey(r.e.LogOrigin(), checkpoint.TypeEd25519, r.e.LogPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	trustJSON, _ := json.Marshal(map[string]any{"logs": []string{vk}, "algs": []string{"ed25519"}, "witnesses_required": 0})
	trust := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trust, trustJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.tkb")
	zipped, err := bundle.Write(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, zipped, 0o600); err != nil {
		t.Fatal(err)
	}
	out, rc := runVerify(t, ref, py, dir, clean, trust)
	if rc != 0 || !hasLine(out, "Integrity: VERIFIED.") {
		t.Fatalf("clean export rejected (rc %d):\n%s", rc, failLines(out))
	}

	// Tamper: edit the run.registered record's run_id, then recompute that file's hash in the manifest.
	name := bundle.RunFile(tenant, runID)
	tampered := make([]bundle.File, len(files))
	copy(tampered, files)
	old := []byte(`"run_id":"` + runID + `"`)
	var runData []byte
	for i := range tampered {
		if tampered[i].Name == name {
			tampered[i].Data = bytes.Replace(tampered[i].Data, old, []byte(`"run_id":"`+runID+`X"`), 1)
			runData = tampered[i].Data
		}
	}
	if runData == nil || bytes.Equal(runData, files[indexOf(files, name)].Data) {
		t.Fatal("the tamper did not change the run file")
	}
	sum := sha256.Sum256(runData)
	for i := range tampered {
		if tampered[i].Name != "manifest.json" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(tampered[i].Data, &m); err != nil {
			t.Fatal(err)
		}
		m["files"].(map[string]any)[name] = hex.EncodeToString(sum[:])
		if tampered[i].Data, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	bad := filepath.Join(dir, "tampered.tkb")
	zipped, err = bundle.Write(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, zipped, 0o600); err != nil {
		t.Fatal(err)
	}
	out, rc = runVerify(t, ref, py, dir, bad, trust)
	// The verifier names the edited record under its signatures check (its golden fixture named it under
	// "chain intact" for a different edit): the requirement is a non-zero exit and that record's seq.
	if rc == 0 || !strings.Contains(out, "[FAIL] signatures") || !strings.Contains(out, fmt.Sprintf("seq %d: hash does not match the event", firstSeq)) {
		t.Fatalf("tampered copy not rejected at seq %d (rc %d):\n%s", firstSeq, rc, out)
	}
}

func indexOf(files []bundle.File, name string) int {
	for i, f := range files {
		if f.Name == name {
			return i
		}
	}
	return -1
}
