// Package checkpoint writes C2SP signed-note checkpoints (signed-note,
// tlog-checkpoint, tlog-cosignature, all v1.1.0), as Tracekit evidence format
// v2 section 6 specifies:
//
//	<origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key id || signature)>\n
//
// The log signs with type 0x01 (Ed25519 over the note text). A witness
// cosigns with type 0x04 (8-byte big-endian time || Ed25519 over
// "cosignature/v1\ntime <t>\n" + text). The log key is separate from every
// record key. The SLH-DSA hybrid line is not implemented.
package checkpoint

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Signature types.
const (
	TypeEd25519   byte = 0x01
	TypeCosigning byte = 0x04
)

const dash = "— " // U+2014 followed by a space

// Body is the note text: origin, tree size and root.
func Body(origin string, size uint64, root [32]byte) (string, error) {
	if err := CheckName(origin); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:])), nil
}

// CheckName rejects key names a verifier would refuse.
func CheckName(name string) error {
	if name == "" || strings.Contains(name, "+") || len(name) > 255 {
		return fmt.Errorf("bad key name %q", name)
	}
	for _, r := range name {
		if r < 0x20 || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return fmt.Errorf("bad key name %q", name)
		}
	}
	return nil
}

// KeyID is the first 4 bytes of SHA-256(name || 0x0A || type || public key).
func KeyID(name string, typ byte, pub ed25519.PublicKey) [4]byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0A, typ})
	h.Write(pub)
	var id [4]byte
	copy(id[:], h.Sum(nil))
	return id
}

// VKey is the pin string: name+hex(key id)+base64(type || public key).
func VKey(name string, typ byte, pub ed25519.PublicKey) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	id := KeyID(name, typ, pub)
	return name + "+" + hex.EncodeToString(id[:]) + "+" + base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...)), nil
}

// ParseSKey reads a note private key: PRIVATE+KEY+name+hex(id)+base64(type || seed).
func ParseSKey(s string) (name string, typ byte, priv ed25519.PrivateKey, err error) {
	const p = "PRIVATE+KEY+"
	if !strings.HasPrefix(s, p) {
		return "", 0, nil, errors.New("not a note private key")
	}
	parts := strings.SplitN(s[len(p):], "+", 3)
	if len(parts) != 3 {
		return "", 0, nil, errors.New("a private key is name+id+key")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 33 {
		return "", 0, nil, errors.New("bad private key encoding")
	}
	priv = ed25519.NewKeyFromSeed(raw[1:])
	want := KeyID(parts[0], raw[0], priv.Public().(ed25519.PublicKey))
	if hex.EncodeToString(want[:]) != parts[1] {
		return "", 0, nil, errors.New("private key id does not match the key")
	}
	return parts[0], raw[0], priv, nil
}

// LogLine is the type 0x01 signature line over the note text.
func LogLine(text, name string, priv ed25519.PrivateKey) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	id := KeyID(name, TypeEd25519, priv.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(priv, []byte(text))
	return line(name, append(id[:], sig...)), nil
}

// CosignLine is a type 0x04 cosignature line made at unix time ts.
func CosignLine(text, name string, priv ed25519.PrivateKey, ts uint64) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	id := KeyID(name, TypeCosigning, priv.Public().(ed25519.PublicKey))
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], ts)
	sig := ed25519.Sign(priv, []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", ts, text)))
	raw := append(append(id[:], t[:]...), sig...)
	return line(name, raw), nil
}

func line(name string, raw []byte) string {
	return dash + name + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
}

// Note joins the text, a blank line and the signature lines.
func Note(text string, lines ...string) string {
	return text + "\n" + strings.Join(lines, "")
}
