package jcs

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Runs the published tests/vectors/jcs.jsonl: 227 canonical rows, 23 error rows.
func TestPublishedVectors(t *testing.T) {
	f, err := os.Open("../../testdata/jcs.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<24)
	var ok, bad int
	for s.Scan() {
		var r struct{ ID, Input, Canonical, SHA256, Error string }
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		got, err := Canonicalize([]byte(r.Input))
		if r.Error != "" {
			if err == nil || !strings.Contains(err.Error(), r.Error) {
				t.Errorf("%s: want error %q, got %v", r.ID, r.Error, err)
			}
			bad++
			continue
		}
		if err != nil || string(got) != r.Canonical || SHA256Hex(got) != "sha256:"+r.SHA256 {
			t.Errorf("%s: got %q err %v, want %q", r.ID, got, err, r.Canonical)
		}
		ok++
	}
	if ok != 227 || bad != 23 {
		t.Fatalf("vector counts: %d canonical, %d error", ok, bad)
	}
}
