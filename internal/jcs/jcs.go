// Package jcs is the engine's only door to canonical JSON. Every hash and
// signature message is computed from strictly parsed input, never from bytes
// that Bao decoded or re-encoded. Parsing and RFC 8785 output come from the
// upstream independent Go verifier; encoding/json is not used for signed bytes.
package jcs

import verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"

// Parse strictly parses JSON text (duplicate keys, non-finite numbers, lone
// surrogates, unsafe integers and excess depth are errors).
func Parse(b []byte) (any, error) { return verifier.ParseStrict(b) }

// Canonical returns the RFC 8785 bytes of a parsed value.
func Canonical(v any) ([]byte, error) { return verifier.Canonical(v) }

// Canonicalize parses then canonicalises.
func Canonicalize(b []byte) ([]byte, error) {
	v, err := Parse(b)
	if err != nil {
		return nil, err
	}
	return Canonical(v)
}

// SHA256Hex is the lowercase hex SHA-256 used in "sha256:<hex>" digests.
func SHA256Hex(b []byte) string { return verifier.SHA256Hex(b) }
