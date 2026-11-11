package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

// decide writes tool.call and then policy.decision. If the second Put fails, the
// retry writes only the decision: one tool.call, one policy.decision, and a later
// reload answers the same request from the log.
func TestDecideResumesAfterPartialWrite(t *testing.T) {
	f := &flaky{Storage: newRig(t).s}
	r := &rig{t: t, e: NewEngine(), s: f}
	runID, tok := r.register(alice, "r1")

	f.puts, f.failAt = 0, 2
	frame := decideFrame(runID, tok, "d1", "c1")
	if got := r.call(alice, frame); code(got) != CodeUnavailable {
		t.Fatalf("second Put failed but the reply was %v", got)
	}
	first := r.call(alice, frame)
	if code(first) != "" || first["decision"] != "deny" {
		t.Fatalf("retry: %v", first)
	}

	counts := map[string]int{}
	keys, _ := f.Storage.List(context.Background(), "records/")
	for _, k := range keys {
		raw, _ := f.Storage.Get(context.Background(), "records/"+k)
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			t.Fatal(err)
		}
		counts[en.Type]++
	}
	if counts["tool.call"] != 1 || counts["policy.decision"] != 1 {
		t.Fatalf("records after resume: %v", counts)
	}

	r2 := &rig{t: t, e: NewEngine(), s: f.Storage}
	again := r2.call(alice, frame)
	a, _ := jcs.Canonical(first)
	b, _ := jcs.Canonical(again)
	if string(a) != string(b) {
		t.Fatalf("reload answered differently:\n%s\n%s", a, b)
	}
}

// A different payload for a started call is refused, and complete checks the digest.
func TestCompleteChecksArgsDigest(t *testing.T) {
	r := newRig(t)
	r.e.Policy = func(string) (string, []string) { return "allow", []string{"T"} }
	runID, tok := r.register(alice, "r1")
	d := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	bad := r.call(alice, `{"method":"complete","request_id":"k1","run_id":"`+runID+`","run_token":"`+tok+
		`","stream":"s","client_seq":1,"tool_call_id":"c1","decision_id":"`+d["decision_id"].(string)+
		`","args_digest":"`+jcs.SHA256Hex([]byte("other"))+`","status":"ok"}`)
	if code(bad) != CodeConflict {
		t.Fatalf("wrong args_digest accepted: %v", bad)
	}
}
