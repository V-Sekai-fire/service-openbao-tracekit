package engine

import (
	"context"
	"encoding/json"
	"testing"

	verifier "github.com/Cygnux-Labs/Tracekit/contrib/independent-go-verifier"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

// Every record the engine writes must pass the upstream event schema and the
// upstream record verifier, for every method and for both allow and deny.
func TestEveryRecordPassesUpstream(t *testing.T) {
	r := newRig(t)
	r.e.Policy = func(tool string) (string, []string) {
		if tool == "bash" {
			return "allow", []string{"TEST-ALLOW"}
		}
		return "deny", []string{"TEST-DENY"}
	}
	runID, tok := r.register(alice, "r1")
	allow := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	deny := r.call(alice, `{"method":"decide","request_id":"d2","run_id":"`+runID+`","run_token":"`+tok+
		`","stream":"s","client_seq":1,"tool_call_id":"c2","tool":"rm","args_source":"parsed","args":{"p":"/"}}`)
	if allow["decision"] != "allow" || deny["decision"] != "deny" {
		t.Fatalf("setup: %v %v", allow, deny)
	}
	digest := argsDigest(t, "bash", "{}")
	done := r.call(alice, `{"method":"complete","request_id":"k1","run_id":"`+runID+`","run_token":"`+tok+
		`","stream":"s","client_seq":2,"tool_call_id":"c1","decision_id":"`+allow["decision_id"].(string)+
		`","args_digest":"`+digest+`","status":"ok"}`)
	if code(done) != "" {
		t.Fatalf("complete refused: %v", done)
	}
	failed := r.call(alice, `{"method":"complete","request_id":"k2","run_id":"`+runID+`","run_token":"`+tok+
		`","stream":"s","client_seq":3,"tool_call_id":"c2","decision_id":"`+deny["decision_id"].(string)+
		`","args_digest":"`+argsDigest(t, "rm", `{"p":"/"}`)+`","status":"error"}`)
	if code(failed) != "" {
		t.Fatalf("error complete refused: %v", failed)
	}
	if got := r.call(alice, `{"method":"close_run","request_id":"x1","run_id":"`+runID+`","run_token":"`+tok+
		`","reason":"done"}`); code(got) != "" {
		t.Fatalf("close_run refused: %v", got)
	}

	ctx := context.Background()
	keys, err := r.s.List(ctx, "records/")
	if err != nil || len(keys) < 6 {
		t.Fatalf("records: %v %v", keys, err)
	}
	for _, k := range keys {
		raw, err := r.s.Get(ctx, "records/"+k)
		if err != nil || raw == nil {
			t.Fatalf("%s: %v", k, err)
		}
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			t.Fatal(err)
		}
		v, err := jcs.Parse([]byte(en.Record))
		if err != nil {
			t.Fatalf("%s is not strict JSON: %v", k, err)
		}
		event := v.(map[string]any)["event"].(map[string]any)
		if err := verifier.ValidateEvent(event); err != nil {
			t.Errorf("%s (%s): schema: %v", k, en.Type, err)
		}
		if _, err := verifier.VerifyRecord([]byte(en.Record), r.e.signer.SPKI); err != nil {
			t.Errorf("%s (%s): verify: %v", k, en.Type, err)
		}
	}
}

// argsDigest is what the Tracekit client computes: sha256(JCS({"tool", "args"})).
func argsDigest(t *testing.T, tool, args string) string {
	t.Helper()
	v, err := jcs.Parse([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	b, err := jcs.Canonical(map[string]any{"tool": tool, "args": v})
	if err != nil {
		t.Fatal(err)
	}
	return jcs.SHA256Hex(b)
}
