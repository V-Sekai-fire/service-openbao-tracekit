// Package record builds and signs Tracekit evidence-format v2 records.
//
// A record is {"v":2,"event","hash","alg","kid","sig"}. hash is
// "sha256:" + hex(SHA-256(JCS(event))). sig is Ed25519 over the JCS of the
// signature message: the event's seven position fields plus alg, kid, hash and
// the domain tag "t":"tracekit.record.v2". Everything signed or hashed goes
// through internal/jcs.
package record

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

// Tag is the domain tag of a record signature.
const Tag = "tracekit.record.v2"

// Alg is the only record algorithm.
const Alg = "ed25519"

// PositionFields are copied from the event into the signature message.
var PositionFields = []string{"log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash"}

// KID is "sha256:" + hex(SHA-256(DER SubjectPublicKeyInfo)).
func KID(spki []byte) string { return jcs.SHA256Hex(spki) }

// SPKI is the DER SubjectPublicKeyInfo of an Ed25519 public key.
func SPKI(pub ed25519.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }

// EventHash is "sha256:" + hex(SHA-256(JCS(event))).
func EventHash(event map[string]any) (string, error) {
	c, err := jcs.Canonical(event)
	if err != nil {
		return "", err
	}
	return jcs.SHA256Hex(c), nil
}

// Message is the canonical signature message of a record.
func Message(event map[string]any, kid, hash string) ([]byte, error) {
	m := map[string]any{"t": Tag, "alg": Alg, "kid": kid, "hash": hash}
	for _, name := range PositionFields {
		v, ok := event[name]
		if !ok {
			return nil, fmt.Errorf("missing event position %s", name)
		}
		m[name] = v
	}
	return jcs.Canonical(m)
}

// Signer signs records with one Ed25519 key.
type Signer struct {
	priv ed25519.PrivateKey
	SPKI []byte
	KID  string
}

// NewSigner derives the SPKI and kid once.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("bad Ed25519 private key")
	}
	spki, err := SPKI(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, SPKI: spki, KID: KID(spki)}, nil
}

// Sign returns the record for event. The event must be parsed (or built) from
// strict JSON values: strings, json.Number, bool, nil, []any, map[string]any.
func (s *Signer) Sign(event map[string]any) (map[string]any, error) {
	h, err := EventHash(event)
	if err != nil {
		return nil, err
	}
	msg, err := Message(event, s.KID, h)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(s.priv, msg)
	return map[string]any{
		"v": json.Number("2"), "event": event, "hash": h,
		"alg": Alg, "kid": s.KID, "sig": base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Line is the canonical one-line JSON of a record.
func Line(rec map[string]any) ([]byte, error) { return jcs.Canonical(rec) }
