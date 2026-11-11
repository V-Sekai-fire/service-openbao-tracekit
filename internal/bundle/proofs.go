package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/checkpoint"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/merkle"
)

// Note returns a checkpoint note for a record tree of the given size and root, signed by
// the log key (type 0x01 over the note text). The verifier pins that key in trust.json.
func Note(origin string, size uint64, root merkle.Hash, name string, priv ed25519.PrivateKey) (string, error) {
	body, err := checkpoint.Body(origin, size, root)
	if err != nil {
		return "", err
	}
	sig, err := checkpoint.LogLine(body, name, priv)
	if err != nil {
		return "", err
	}
	return checkpoint.Note(body, sig), nil
}

// Proofs returns the RFC 6962 inclusion proof of each index in leaves, as base64 hashes
// (format v2 section 9, proofs/records.json).
func Proofs(leaves []merkle.Hash, indices []int) (map[int][]string, error) {
	out := make(map[int][]string, len(indices))
	for _, i := range indices {
		p, err := merkle.InclusionProof(i, leaves)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		enc := make([]string, len(p))
		for j, h := range p {
			enc[j] = base64.StdEncoding.EncodeToString(h[:])
		}
		out[i] = enc
	}
	return out, nil
}
