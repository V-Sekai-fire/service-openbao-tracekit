package engine

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// A refused approval_consume is recorded as approval.refused, and a retry with the
// same request_id writes nothing new and gets the same answer. A new request_id
// writes a second record.
func TestRefusedConsumeIsRecorded(t *testing.T) {
	r := newRig(t) // default policy denies: the call is not allowed, so consume refuses
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	before := countRecords(t, r.s)

	a := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if a["ok"] != false {
		t.Fatalf("refused consume answered ok: %v", a)
	}
	if n := countRecords(t, r.s); n != before+1 {
		t.Fatalf("first refusal wrote %d records, want 1", n-before)
	}

	b := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if n := countRecords(t, r.s); n != before+1 {
		t.Fatalf("replay with the same request_id wrote %d records, want 0", n-before-1)
	}
	if b["ok"] != a["ok"] || consumeRule(b) != consumeRule(a) {
		t.Fatalf("replay answer differs: %v vs %v", a, b)
	}

	r.call(alice, consumeFrame(runID, tok, "c1", "rm", "{}"))
	if n := countRecords(t, r.s); n != before+2 {
		t.Fatalf("new request_id wrote %d records in total, want 2", n-before)
	}
}

// countRecords counts signed records. countKeys lists top-level names, so it
// sees "records/" once however many records there are; this one counts them.
func countRecords(t *testing.T, s logical.Storage) int {
	t.Helper()
	keys, err := s.List(context.Background(), "records/")
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}
