package record

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

type row struct {
	ID      string          `json:"id"`
	Public  string          `json:"public"`
	Message string          `json:"message"`
	Record  json.RawMessage `json:"record"`
}

func rows(t *testing.T) []row {
	t.Helper()
	f, err := os.Open("../../testdata/sig_v2.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<24)
	var out []row
	for s.Scan() {
		var r row
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.Message != "" {
			out = append(out, r)
		}
	}
	return out
}

// The three published record rows: our hash, kid and signature message equal
// the vector's, and the upstream verifier accepts the record.
func TestPublishedRecords(t *testing.T) {
	rs := rows(t)
	if len(rs) != 3 {
		t.Fatalf("want 3 record rows, got %d", len(rs))
	}
	for _, r := range rs {
		t.Run(r.ID, func(t *testing.T) {
			pub, err := hex.DecodeString(r.Public)
			if err != nil {
				t.Fatal(err)
			}
			spki, err := SPKI(ed25519.PublicKey(pub))
			if err != nil {
				t.Fatal(err)
			}
			v, err := jcs.Parse(r.Record)
			if err != nil {
				t.Fatal(err)
			}
			rec := v.(map[string]any)
			event := rec["event"].(map[string]any)
			h, err := EventHash(event)
			if err != nil || h != rec["hash"] {
				t.Fatalf("hash %q err %v, want %v", h, err, rec["hash"])
			}
			if KID(spki) != rec["kid"] {
				t.Fatalf("kid %q, want %v", KID(spki), rec["kid"])
			}
			msg, err := Message(event, KID(spki), h)
			if err != nil || string(msg) != r.Message {
				t.Fatalf("message %q err %v, want %q", msg, err, r.Message)
			}
			if _, err := verifier.VerifyRecord(r.Record, spki); err != nil {
				t.Fatalf("upstream verifier: %v", err)
			}
		})
	}
}

func event(t *testing.T) map[string]any {
	t.Helper()
	zero := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	v, err := jcs.Parse([]byte(`{"schema_version":"tracekit.event.v2","seq":0,"run_seq":0,` +
		`"log_id":"0123456789abcdef0123456789abcdef","tenant":"acme","run_id":"run-1",` +
		`"prev_hash":"` + zero + `","run_prev_hash":"` + zero + `","type":"tool.call","data":{"tool":"bash"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// A record signed here passes the upstream verifier; changing any one field
// of the record makes it fail.
func TestSignThenVerifyAndMutate(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.Sign(event(t))
	if err != nil {
		t.Fatal(err)
	}
	line, err := Line(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyRecord(line, s.SPKI); err != nil {
		t.Fatalf("fresh record rejected: %v", err)
	}
	mutations := map[string]func(m map[string]any){
		"event.seq":    func(m map[string]any) { m["event"].(map[string]any)["seq"] = json.Number("1") },
		"event.data":   func(m map[string]any) { m["event"].(map[string]any)["data"] = map[string]any{"tool": "rm"} },
		"event.tenant": func(m map[string]any) { m["event"].(map[string]any)["tenant"] = "evil" },
		"hash": func(m map[string]any) {
			m["hash"] = "sha256:" + string(make([]byte, 0)) + hex.EncodeToString(make([]byte, 32))
		},
		"kid": func(m map[string]any) { m["kid"] = "sha256:" + hex.EncodeToString(make([]byte, 32)) },
		"sig": func(m map[string]any) { m["sig"] = "AAAA" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			again, _ := s.Sign(event(t))
			mutate(again)
			b, err := Line(again)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.VerifyRecord(b, s.SPKI); err == nil {
				t.Fatal("mutated record accepted")
			}
		})
	}
}

func TestLeafData(t *testing.T) {
	d, err := LeafData("sha256:" + hex.EncodeToString(make([]byte, 32)))
	if err != nil || len(d) != 32 {
		t.Fatalf("got %d bytes, err %v", len(d), err)
	}
	for _, bad := range []string{"", "sha256:00", "md5:" + hex.EncodeToString(make([]byte, 32)), "sha256:" + "zz" + hex.EncodeToString(make([]byte, 31))} {
		if _, err := LeafData(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Only canonical lowercase hex is a record hash, as upstream requires.
func TestLeafDataStrict(t *testing.T) {
	good := strings.Repeat("ab", 32)
	if _, err := LeafData("sha256:" + good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"sha256:" + strings.ToUpper(good),
		"sha256: " + good[1:],
		"sha256:" + good[:63] + "g",
		" sha256:" + good,
	} {
		if _, err := LeafData(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
