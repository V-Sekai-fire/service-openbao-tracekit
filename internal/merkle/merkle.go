// Package merkle is the RFC 6962 / RFC 9162 tree used by the Tracekit record log.
// Leaf hash = SHA-256(0x00 || data), node hash = SHA-256(0x01 || left || right),
// empty tree = SHA-256(""). Hashes are raw 32-byte values.
package merkle

import (
	"crypto/sha256"
	"errors"
)

// Hash is a raw SHA-256 value.
type Hash = [32]byte

// LeafHash hashes leaf data.
func LeafHash(data []byte) Hash { return sha256.Sum256(append([]byte{0}, data...)) }

// NodeHash hashes two children.
func NodeHash(l, r Hash) Hash {
	b := make([]byte, 0, 65)
	b = append(b, 1)
	b = append(b, l[:]...)
	b = append(b, r[:]...)
	return sha256.Sum256(b)
}

// k is the largest power of two strictly less than n (n > 1).
func k(n int) int {
	p := 1
	for p<<1 < n {
		p <<= 1
	}
	return p
}

// Root is MTH(D[n]) over leaf hashes.
func Root(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	s := k(len(leaves))
	return NodeHash(Root(leaves[:s]), Root(leaves[s:]))
}

// InclusionProof is PATH(m, D[n]).
func InclusionProof(m int, leaves []Hash) ([]Hash, error) {
	n := len(leaves)
	if m < 0 || m >= n {
		return nil, errors.New("leaf index out of range")
	}
	if n == 1 {
		return nil, nil
	}
	s := k(n)
	if m < s {
		p, _ := InclusionProof(m, leaves[:s])
		return append(p, Root(leaves[s:])), nil
	}
	p, _ := InclusionProof(m-s, leaves[s:])
	return append(p, Root(leaves[:s])), nil
}

// ConsistencyProof is PROOF(m, D[n]) for 0 < m <= n.
func ConsistencyProof(m int, leaves []Hash) ([]Hash, error) {
	n := len(leaves)
	if m <= 0 || m > n {
		return nil, errors.New("bad sizes for a consistency proof")
	}
	return subProof(m, leaves, true), nil
}

func subProof(m int, d []Hash, complete bool) []Hash {
	n := len(d)
	if m == n {
		if complete {
			return nil
		}
		return []Hash{Root(d)}
	}
	s := k(n)
	if m <= s {
		return append(subProof(m, d[:s], complete), Root(d[s:]))
	}
	return append(subProof(m-s, d[s:], false), Root(d[:s]))
}
