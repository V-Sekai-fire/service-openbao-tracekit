package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/merkle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/record"
)

type vec struct {
	LogSKey string `json:"log_skey"`
	LogVKey string `json:"log_vkey"`
	WitVKey string `json:"wit_vkey"`
	Text    string `json:"text"`
	Note    string `json:"note"`
}

func load(t *testing.T) vec {
	t.Helper()
	b, err := os.ReadFile("../../testdata/c2sp_checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Our log signature, witness cosignature, vkeys and note equal the published
// vector byte for byte. The witness seed is sha256("witness"), per the vector.
func TestPublishedVectorByteForByte(t *testing.T) {
	v := load(t)
	name, typ, logPriv, err := ParseSKey(v.LogSKey)
	if err != nil || typ != TypeEd25519 {
		t.Fatalf("skey: %v type %d", err, typ)
	}
	logV, err := VKey(name, TypeEd25519, logPriv.Public().(ed25519.PublicKey))
	if err != nil || logV != v.LogVKey {
		t.Fatalf("log vkey %q, want %q (%v)", logV, v.LogVKey, err)
	}
	lines := strings.SplitAfter(strings.TrimPrefix(v.Note, v.Text+"\n"), "\n")
	if len(lines) != 3 || lines[2] != "" {
		t.Fatalf("vector note has %d signature lines", len(lines)-1)
	}
	logLine, err := LogLine(v.Text, name, logPriv)
	if err != nil || logLine != lines[0] {
		t.Fatalf("log line\n got %q\nwant %q (%v)", logLine, lines[0], err)
	}
	seed := sha256.Sum256([]byte("witness"))
	witPriv := ed25519.NewKeyFromSeed(seed[:])
	witV, err := VKey("witness.example.org/w1", TypeCosigning, witPriv.Public().(ed25519.PublicKey))
	if err != nil || witV != v.WitVKey {
		t.Fatalf("witness vkey %q, want %q (%v)", witV, v.WitVKey, err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Fields(lines[1])[len(strings.Fields(lines[1]))-1])
	if err != nil || len(raw) != 4+8+64 {
		t.Fatalf("witness line: %v len %d", err, len(raw))
	}
	ts := binary.BigEndian.Uint64(raw[4:12])
	cos, err := CosignLine(v.Text, "witness.example.org/w1", witPriv, ts)
	if err != nil || cos != lines[1] {
		t.Fatalf("cosign line\n got %q\nwant %q (%v)", cos, lines[1], err)
	}
	if got := Note(v.Text, logLine, cos); got != v.Note {
		t.Fatalf("assembled note differs from the vector")
	}
	// And the upstream verifier accepts the published note at quorum 1.
	lk, err := verifier.ParseVKey(v.LogVKey)
	if err != nil {
		t.Fatal(err)
	}
	wk, err := verifier.ParseVKey(v.WitVKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyCheckpoint([]byte(v.Note), lk, []verifier.VKey{wk}, 1); err != nil {
		t.Fatalf("upstream rejects the vector: %v", err)
	}
}

type keys struct {
	origin   string
	logPriv  ed25519.PrivateKey
	witPriv  ed25519.PrivateKey
	logV, wV verifier.VKey
}

func newKeys(t *testing.T) keys {
	t.Helper()
	_, lp, _ := ed25519.GenerateKey(rand.Reader)
	_, wp, _ := ed25519.GenerateKey(rand.Reader)
	k := keys{origin: "tracekit.test/log/abc", logPriv: lp, witPriv: wp}
	lv, _ := VKey(k.origin, TypeEd25519, lp.Public().(ed25519.PublicKey))
	wv, _ := VKey("w.test/one", TypeCosigning, wp.Public().(ed25519.PublicKey))
	var err error
	if k.logV, err = verifier.ParseVKey(lv); err != nil {
		t.Fatal(err)
	}
	if k.wV, err = verifier.ParseVKey(wv); err != nil {
		t.Fatal(err)
	}
	return k
}

func (k keys) note(t *testing.T, size uint64, root [32]byte, cosign bool) (text, note string) {
	t.Helper()
	text, err := Body(k.origin, size, root)
	if err != nil {
		t.Fatal(err)
	}
	ll, _ := LogLine(text, k.origin, k.logPriv)
	if !cosign {
		return text, Note(text, ll)
	}
	cl, _ := CosignLine(text, "w.test/one", k.witPriv, 1760000000)
	return text, Note(text, ll, cl)
}

func TestRoundTripAgainstUpstream(t *testing.T) {
	k := newKeys(t)
	root := merkle.Root([]merkle.Hash{merkle.LeafHash([]byte("a"))})
	_, plain := k.note(t, 1, root, false)
	if _, err := verifier.VerifyCheckpoint([]byte(plain), k.logV, nil, 0); err != nil {
		t.Fatalf("log-only note rejected: %v", err)
	}
	if _, err := verifier.VerifyCheckpoint([]byte(plain), k.logV, []verifier.VKey{k.wV}, 1); err == nil {
		t.Fatal("quorum 1 met without a cosignature")
	}
	_, both := k.note(t, 1, root, true)
	cp, err := verifier.VerifyCheckpoint([]byte(both), k.logV, []verifier.VKey{k.wV}, 1)
	if err != nil || cp.Size != 1 || cp.Witnesses != 1 {
		t.Fatalf("cosigned note: %+v %v", cp, err)
	}
}

func TestRejections(t *testing.T) {
	k := newKeys(t)
	root := merkle.Root([]merkle.Hash{merkle.LeafHash([]byte("a")), merkle.LeafHash([]byte("b"))})
	text, note := k.note(t, 2, root, true)
	mutate := map[string]string{
		"size edited":     strings.Replace(note, "\n2\n", "\n3\n", 1),
		"leading zero":    strings.Replace(note, "\n2\n", "\n02\n", 1),
		"origin edited":   strings.Replace(note, k.origin, k.origin+"x", 1),
		"root edited":     strings.Replace(note, text[len(k.origin)+3:len(k.origin)+4], "A", 1),
		"no blank line":   strings.Replace(note, "\n\n", "\n", 1),
		"no signature":    text + "\n",
		"ascii dash":      strings.Replace(note, "— ", "- ", 1),
		"wrong cosigner":  strings.Replace(note, "w.test/one", "w.test/two", 1),
		"flipped log sig": flip(t, note, k.origin),
	}
	for name, n := range mutate {
		if n == note {
			t.Fatalf("%s: mutation did not change the note", name)
		}
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.VerifyCheckpoint([]byte(n), k.logV, []verifier.VKey{k.wV}, 1); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("same line twice", func(t *testing.T) {
		ll, _ := LogLine(text, k.origin, k.logPriv)
		if _, err := verifier.VerifyCheckpoint([]byte(Note(text, ll, ll)), k.logV, nil, 0); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("65 signature lines", func(t *testing.T) {
		ll, _ := LogLine(text, k.origin, k.logPriv)
		lines := []string{ll}
		for i := 0; i < 64; i++ {
			lines = append(lines, line(fmt.Sprintf("other.test/%d", i), make([]byte, 68)))
		}
		if _, err := verifier.VerifyCheckpoint([]byte(Note(text, lines...)), k.logV, nil, 0); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("bad key names", func(t *testing.T) {
		for _, n := range []string{"", "a b", "a+b", "a\nb", strings.Repeat("x", 256)} {
			if _, err := Body(n, 1, root); err == nil {
				t.Errorf("accepted %q", n)
			}
		}
	})
}

func flip(t *testing.T, note, origin string) string {
	t.Helper()
	i := strings.Index(note, dash+origin+" ")
	start := i + len(dash+origin+" ")
	end := start + strings.Index(note[start:], "\n")
	raw, err := base64.StdEncoding.DecodeString(note[start:end])
	if err != nil {
		t.Fatal(err)
	}
	raw[10] ^= 1
	return note[:start] + base64.StdEncoding.EncodeToString(raw) + note[end:]
}

// Chained signed records, a tree over their hashes, a signed checkpoint, and
// an upstream-verified inclusion proof for every record against its root.
func TestEndToEnd(t *testing.T) {
	k := newKeys(t)
	_, rp, _ := ed25519.GenerateKey(rand.Reader)
	s, err := record.NewSigner(rp)
	if err != nil {
		t.Fatal(err)
	}
	const n = 21
	zero := "sha256:" + hex.EncodeToString(make([]byte, 32))
	prev := zero
	var hashes []string
	var leaves []merkle.Hash
	for i := 0; i < n; i++ {
		ev := map[string]any{
			"schema_version": "tracekit.event.v2", "log_id": "0123456789abcdef0123456789abcdef",
			"seq": json.Number(fmt.Sprint(i)), "run_seq": json.Number(fmt.Sprint(i)), "tenant": "acme", "run_id": "run-1",
			"prev_hash": prev, "run_prev_hash": prev, "type": "tool.call", "data": map[string]any{"i": json.Number(fmt.Sprint(i))},
		}
		rec, err := s.Sign(ev)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := record.Line(rec)
		if _, err := verifier.VerifyRecord(b, s.SPKI); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		h := rec["hash"].(string)
		data, err := record.LeafData(h)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, h)
		leaves = append(leaves, merkle.LeafHash(data))
		prev = h
	}
	root := merkle.Root(leaves)
	_, note := k.note(t, n, root, true)
	cp, err := verifier.VerifyCheckpoint([]byte(note), k.logV, []verifier.VKey{k.wV}, 1)
	if err != nil || cp.Size != n {
		t.Fatalf("checkpoint: %+v %v", cp, err)
	}
	for i := 0; i < n; i++ {
		p, _ := merkle.InclusionProof(i, leaves)
		ps := make([]string, len(p))
		for j, h := range p {
			ps[j] = base64.StdEncoding.EncodeToString(h[:])
		}
		if err := verifier.VerifyInclusion(hashes[i], uint64(i), n, ps, root); err != nil {
			t.Fatalf("record %d not included: %v", i, err)
		}
	}
}
