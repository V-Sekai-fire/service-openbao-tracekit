package engine

import (
	"fmt"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

// A non-zero attempt is carried on the call and its decision, so a retry of the same tool call
// with a new attempt is a distinct decision, not a conflict with the first.
func TestNonZeroAttemptIsCarried(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	frame := `{"method":"decide","request_id":"d1","run_id":"` + runID + `","run_token":"` + tok +
		`","stream":"s","client_seq":1,"tool_call_id":"c1","attempt":2,"tool":"bash","args_source":"parsed","args":{}}`
	if m := r.call(alice, frame); code(m) != "" || m["decision"] != "allow" {
		t.Fatalf("attempt 2 decide: %v", m)
	}
	found := false
	for _, en := range entriesOf(t, r.s) {
		if en.Type != "policy.decision" {
			continue
		}
		v, err := jcs.Parse([]byte(en.Record))
		if err != nil {
			t.Fatal(err)
		}
		ev := v.(map[string]any)["event"].(map[string]any)
		data := ev["data"].(map[string]any)
		got := fmt.Sprint(ev["attempt"])
		if got == "" || got == "<nil>" {
			got = fmt.Sprint(data["attempt"])
		}
		if got != "2" {
			t.Fatalf("policy.decision attempt is %q, want 2", got)
		}
		found = true
	}
	if !found {
		t.Fatal("no policy.decision record")
	}
}
