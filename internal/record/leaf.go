package record

import (
	"encoding/hex"
	"errors"
	"strings"
)

// LeafData is the Merkle leaf input of a record: the 32 raw bytes of its hash.
// Only canonical lowercase "sha256:<64 hex>" is accepted, as upstream requires.
func LeafData(hash string) ([]byte, error) {
	const p = "sha256:"
	if !strings.HasPrefix(hash, p) || len(hash) != len(p)+64 {
		return nil, errors.New("bad record hash")
	}
	out, err := hex.DecodeString(hash[len(p):])
	if err != nil || hex.EncodeToString(out) != hash[len(p):] {
		return nil, errors.New("bad record hash")
	}
	return out, nil
}
