package merkle

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"
)

func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = LeafHash([]byte(fmt.Sprintf("record-%d", i)))
	}
	return out
}

func b64s(hs []Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

func TestEmptyRoot(t *testing.T) {
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	r := Root(nil)
	if hex.EncodeToString(r[:]) != want {
		t.Fatalf("empty root %x", r)
	}
}

// The documented worked example: leaf hash of record-signer-epoch.
func TestDocLeafHash(t *testing.T) {
	data, _ := hex.DecodeString("db5045e1f08ce84b3f4af68706546c4db460adbef48568a7206ba5cc73f73dc6")
	const want = "252e000747132185f241d03274ef087f1eccb5d708dc18b49c9d990f21059060"
	h := LeafHash(data)
	if hex.EncodeToString(h[:]) != want {
		t.Fatalf("leaf hash %x", h)
	}
}

// Every inclusion proof for every size up to 70 passes the upstream verifier.
// The verifier takes the record hash and hashes it as a leaf, so each test
// "record hash" is the leaf data and the leaf hashes are built from it.
func TestInclusionAgainstUpstream(t *testing.T) {
	for n := 1; n <= 70; n++ {
		data := make([][32]byte, n)
		ls := make([]Hash, n)
		for i := range data {
			data[i] = [32]byte{byte(i), byte(n)}
			ls[i] = LeafHash(data[i][:])
		}
		root := Root(ls)
		for m := 0; m < n; m++ {
			p, err := InclusionProof(m, ls)
			if err != nil {
				t.Fatal(err)
			}
			rh := "sha256:" + hex.EncodeToString(data[m][:])
			if err := verifier.VerifyInclusion(rh, uint64(m), uint64(n), b64s(p), root); err != nil {
				t.Fatalf("size %d index %d: %v", n, m, err)
			}
			if n > 1 {
				bad := Hash{9}
				if err := verifier.VerifyInclusion(rh, uint64(m), uint64(n), b64s(p), bad); err == nil {
					t.Fatalf("size %d index %d: wrong root accepted", n, m)
				}
			}
		}
	}
}

// Every consistency proof for every pair of sizes up to 40 passes upstream.
func TestConsistencyAgainstUpstream(t *testing.T) {
	for n := 1; n <= 40; n++ {
		ls := leaves(n)
		newRoot := Root(ls)
		for m := 1; m <= n; m++ {
			p, err := ConsistencyProof(m, ls)
			if err != nil {
				t.Fatal(err)
			}
			oldRoot := Root(ls[:m])
			if err := verifier.VerifyConsistency(uint64(m), uint64(n), oldRoot, newRoot, b64s(p)); err != nil {
				t.Fatalf("sizes %d to %d: %v", m, n, err)
			}
		}
	}
}

func TestProofBounds(t *testing.T) {
	if _, err := InclusionProof(3, leaves(3)); err == nil {
		t.Error("index out of range accepted")
	}
	if _, err := ConsistencyProof(0, leaves(3)); err == nil {
		t.Error("size 0 accepted")
	}
	if _, err := ConsistencyProof(4, leaves(3)); err == nil {
		t.Error("old size above new size accepted")
	}
}
