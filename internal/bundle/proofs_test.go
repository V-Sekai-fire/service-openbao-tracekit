package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/merkle"
)

// verifyInclusion is RFC 9162 section 2.1.3.2: it rebuilds the root from a leaf and its proof.
func verifyInclusion(index, size int, leaf merkle.Hash, proof []merkle.Hash) merkle.Hash {
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if fn&1 == 1 || fn == sn {
			r = merkle.NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = merkle.NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

func TestProofsRebuildTheRoot(t *testing.T) {
	var leaves []merkle.Hash
	for i := 0; i < 13; i++ {
		leaves = append(leaves, merkle.LeafHash([]byte{byte(i)}))
	}
	root := merkle.Root(leaves)
	idx := []int{0, 5, 12}
	enc, err := Proofs(leaves, idx)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range idx {
		var proof []merkle.Hash
		for _, s := range enc[i] {
			raw, err := base64.StdEncoding.DecodeString(s)
			if err != nil || len(raw) != 32 {
				t.Fatalf("index %d: bad proof element", i)
			}
			var h merkle.Hash
			copy(h[:], raw)
			proof = append(proof, h)
		}
		if got := verifyInclusion(i, len(leaves), leaves[i], proof); got != root {
			t.Errorf("index %d: proof does not rebuild the root", i)
		}
	}
}

func TestNoteSignatureVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var root merkle.Hash
	root[0] = 7
	note, err := Note("tracekit.test/log", 13, root, "tracekit.test/log", priv)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(note, "\n\n", 2)
	if len(parts) != 2 {
		t.Fatal("the note has no blank line before its signatures")
	}
	body := parts[0] + "\n"
	sigLine := strings.TrimSuffix(parts[1], "\n")
	fields := strings.Fields(sigLine)
	if len(fields) != 3 || fields[0] != "—" {
		t.Fatalf("signature line %q", sigLine)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(raw) != 4+ed25519.SignatureSize {
		t.Fatal("bad signature encoding")
	}
	if !ed25519.Verify(pub, []byte(body), raw[4:]) {
		t.Fatal("the log signature does not verify over the note body")
	}
	if bytes.Equal(raw[:4], make([]byte, 4)) {
		t.Fatal("key id is zero")
	}
}
