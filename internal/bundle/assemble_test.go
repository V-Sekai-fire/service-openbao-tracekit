package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// line is a strict JSON text of more than 256 bytes, like a signed record.
func line(id string) string {
	return `{"id":"` + id + `","pad":"` + strings.Repeat("x", 260) + `"}`
}

func TestAssembleManifestListsEveryFile(t *testing.T) {
	runName := RunFile("acme", "run-1")
	files, err := Assemble(map[string][]string{runName: {line("a"), line("b")}}, []string{line("k")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(files); err != nil {
		t.Fatalf("the files do not zip: %v", err)
	}
	byName := map[string][]byte{}
	for _, f := range files {
		byName[f.Name] = f.Data
	}
	var m struct {
		Format string            `json:"format"`
		Files  map[string]string `json:"files"`
	}
	if err := json.Unmarshal(byName["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != formatName {
		t.Fatalf("format %q", m.Format)
	}
	if len(m.Files) != len(files)-1 {
		t.Fatalf("manifest lists %d files, bundle has %d besides itself", len(m.Files), len(files)-1)
	}
	for name, want := range m.Files {
		sum := sha256.Sum256(byName[name])
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s: manifest hash does not match its bytes", name)
		}
	}
	wantRuns := line("a") + "\n" + line("b") + "\n"
	if string(byName[runName]) != wantRuns {
		t.Error("run lines are not used verbatim")
	}
}

func TestAssembleRefusesBadLines(t *testing.T) {
	name := RunFile("acme", "run-1")
	if _, err := Assemble(map[string][]string{name: {"{}"}}, nil); err == nil {
		t.Error("a line under 256 bytes was accepted")
	}
	if _, err := Assemble(map[string][]string{name: {line("a") + "\n" + line("b")}}, nil); err == nil {
		t.Error("a line with a newline was accepted")
	}
}

func TestRunFileNameShape(t *testing.T) {
	n := RunFile("acme", "run-1")
	if !strings.HasPrefix(n, "runs/") || !strings.HasSuffix(n, ".jsonl") || len(n) != len("runs/")+32+len(".jsonl") {
		t.Fatalf("run file name %q", n)
	}
	if bytes.Equal([]byte(n), []byte(RunFile("acme", "run-2"))) {
		t.Fatal("different runs share a file name")
	}
}
