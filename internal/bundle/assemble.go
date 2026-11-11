package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Bounds on a JSON lines file (format v2, section 9): one strict JSON text per line,
// at least 256 bytes (no signed record is shorter) and at most 1 MiB.
const (
	minLineBytes = 256
	maxLineBytes = 1 << 20
	formatName   = "tracekit.bundle.v2"
	verifierMin  = "0.4.0"
)

// RunFile is the bundle name of one run's records: runs/<id>.jsonl, where id is the
// first 32 hex of SHA-256("<tenant>/<run_id>").
func RunFile(tenant, runID string) string {
	sum := sha256.Sum256([]byte(tenant + "/" + runID))
	return "runs/" + hex.EncodeToString(sum[:])[:32] + ".jsonl"
}

// jsonl joins lines, each followed by a newline, after checking each one's bounds.
func jsonl(lines []string) ([]byte, error) {
	var b strings.Builder
	for _, l := range lines {
		if len(l) < minLineBytes || len(l) > maxLineBytes {
			return nil, fmt.Errorf("line of %d bytes: outside [%d, %d]", len(l), minLineBytes, maxLineBytes)
		}
		if strings.ContainsRune(l, '\n') {
			return nil, fmt.Errorf("a line contains a newline")
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// Assemble builds the bundle files that are not proofs or checkpoints: one JSON lines
// file per run (keys are RunFile names; lines are the stored records, in run_seq order,
// used verbatim), keys/records.jsonl, and manifest.json listing each file's SHA-256.
// The output does not verify on its own: proofs and a checkpoint are still missing.
func Assemble(runs map[string][]string, keys []string) ([]File, error) {
	var files []File
	names := make([]string, 0, len(runs))
	for n := range runs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := jsonl(runs[n])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		files = append(files, File{Name: n, Data: data})
	}
	keyData, err := jsonl(keys)
	if err != nil {
		return nil, fmt.Errorf("keys/records.jsonl: %w", err)
	}
	files = append(files, File{Name: "keys/records.jsonl", Data: keyData})

	listed := make(map[string]string, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		listed[f.Name] = hex.EncodeToString(sum[:])
	}
	manifest, err := json.Marshal(struct {
		Format      string            `json:"format"`
		VerifierMin string            `json:"verifier_min_version"`
		Files       map[string]string `json:"files"`
	}{formatName, verifierMin, listed})
	if err != nil {
		return nil, err
	}
	return append(files, File{Name: "manifest.json", Data: manifest}), nil
}
