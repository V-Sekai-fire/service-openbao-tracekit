package engine

import "crypto/ed25519"

// LogPublicKey is the public key that signs the log's checkpoints. It is derived from a
// seed separate from the record signer's, is never exported, and is pinned by a verifier
// in trust.json (`logs`). Valid once the state is loaded.
func (e *Engine) LogPublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(e.cfg.LogSeed).Public().(ed25519.PublicKey)
}
