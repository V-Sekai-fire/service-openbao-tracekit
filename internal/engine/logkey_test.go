package engine

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// The log key is stable across a reload and is not the record signer's key.
func TestLogKeyStableAndSeparate(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	logPub := r.e.LogPublicKey()
	if len(logPub) != ed25519.PublicKeySize {
		t.Fatalf("log key length %d", len(logPub))
	}
	recordPub := ed25519.NewKeyFromSeed(r.e.cfg.Seed).Public().(ed25519.PublicKey)
	if bytes.Equal(logPub, recordPub) {
		t.Fatal("log key equals the record signer key")
	}
	r2 := &rig{t: t, e: NewEngine(), s: r.s}
	r2.call(alice, decideFrame(runID, tok, "d2", "c2"))
	if !bytes.Equal(r2.e.LogPublicKey(), logPub) {
		t.Fatal("log key changed after reload")
	}
}
