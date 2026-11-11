package engine

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func putPolicy(t *testing.T, r *rig, body string) {
	t.Helper()
	if err := r.s.Put(context.Background(), &logical.StorageEntry{Key: policyKey, Value: []byte(body)}); err != nil {
		t.Fatal(err)
	}
}

// With nothing stored, the engine's own policy applies: the default denies.
func TestNoStoredPolicyDenies(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	if m := r.call(alice, decideFrame(runID, tok, "d1", "c1")); m["decision"] != "deny" {
		t.Fatalf("default did not deny: %v", m)
	}
}

// A stored allow list allows exactly the tools it names, even with the engine's
// own policy set to deny.
func TestStoredAllowListAllowsNamedTool(t *testing.T) {
	r := newRig(t)
	putPolicy(t, r, `{"allow":["bash"]}`)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m["decision"] != "allow" {
		t.Fatalf("stored allow not applied: %v", m)
	}
	rules, _ := m["rule_ids"].([]any)
	if len(rules) != 1 || rules[0] != "TK-STORED-ALLOW" {
		t.Fatalf("rule ids: %v", m["rule_ids"])
	}
}

// A tool the stored list does not name is denied.
func TestStoredAllowListDeniesOtherTool(t *testing.T) {
	r := newRig(t)
	putPolicy(t, r, `{"allow":["bash"]}`)
	runID, tok := r.register(alice, "r1")
	frame := `{"method":"decide","request_id":"d2","run_id":"` + runID + `","run_token":"` + tok +
		`","stream":"s","client_seq":1,"tool_call_id":"c2","tool":"rm","args_source":"parsed","args":{"p":"/"}}`
	if m := r.call(alice, frame); m["decision"] != "deny" {
		t.Fatalf("unlisted tool was not denied: %v", m)
	}
}

// A stored policy that cannot be parsed fails closed: nothing is allowed.
func TestInvalidStoredPolicyFailsClosed(t *testing.T) {
	r := newRig(t)
	r.e.Policy = func(string) (string, []string) { return "allow", []string{"X"} }
	putPolicy(t, r, `{"allow":["bash"],"extra":1}`)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m["decision"] != "deny" {
		t.Fatalf("invalid policy did not fail closed: %v", m)
	}
}
