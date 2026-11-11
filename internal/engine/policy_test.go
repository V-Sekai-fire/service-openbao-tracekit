package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
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

// Stored policies must parse strictly and have exactly one shape. Each of these
// fails closed with TK-POLICY-INVALID, not just a generic deny.
func TestInvalidStoredShapesFailClosedWithRule(t *testing.T) {
	bodies := []string{
		`{"allow":["bash"]}}`,               // trailing brace
		`{"allow":["bash"]} {"allow":[]}`,   // second object
		`{"allow":["bash"],"allow":["rm"]}`, // duplicate key
		`{"allow":["bash"],"extra":1}`,      // unknown key
		`{"allow":"bash"}`,                  // not an array
		`{"allow":[1]}`,                     // non-string element
		`{"allow":[""]}`,                    // empty tool name
		`{"allow":null}`,                    // null list
		`null`,                              // not an object
		`[]`,                                // not an object
		``,                                  // empty value
	}
	for _, b := range bodies {
		r := newRig(t)
		r.e.Policy = func(string) (string, []string) { return "allow", []string{"X"} }
		putPolicy(t, r, b)
		runID, tok := r.register(alice, "r1")
		m := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
		if m["decision"] != "deny" {
			t.Errorf("body %q: not denied: %v", b, m)
			continue
		}
		rules, _ := m["rule_ids"].([]any)
		if len(rules) != 1 || rules[0] != "TK-POLICY-INVALID" {
			t.Errorf("body %q: rule ids %v, want [TK-POLICY-INVALID]", b, m["rule_ids"])
		}
	}
}

// A valid empty allow list is a real policy: it denies everything, with TK-STORED-DENY.
func TestEmptyAllowListDeniesWithStoredRule(t *testing.T) {
	r := newRig(t)
	putPolicy(t, r, `{"allow":[]}`)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	rules, _ := m["rule_ids"].([]any)
	if m["decision"] != "deny" || len(rules) != 1 || rules[0] != "TK-STORED-DENY" {
		t.Fatalf("empty list: %v", m)
	}
}

// A write without the allow field is refused, so a typo cannot lock every tool out.
func TestPolicyWriteWithoutAllowIsRefused(t *testing.T) {
	r := newRig(t)
	p := r.e.policyPath()
	req := &logical.Request{Storage: r.s, Operation: logical.UpdateOperation}
	resp, err := p.Operations[logical.UpdateOperation].Handler()(context.Background(), req, &framework.FieldData{Raw: map[string]interface{}{}, Schema: p.Fields})
	if err == nil {
		t.Fatalf("write without allow was accepted: %v", resp)
	}
	if ent, _ := r.s.Get(context.Background(), policyKey); ent != nil {
		t.Fatalf("a refused write still stored a policy: %s", ent.Value)
	}
}

// If reading the stored policy fails, the call is refused as unavailable and
// nothing is written; the next call with healthy storage succeeds.
type getFailStorage struct {
	logical.Storage
	fail bool
}

func (g *getFailStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if g.fail && key == policyKey {
		return nil, errors.New("storage read failed")
	}
	return g.Storage.Get(ctx, key)
}

func TestPolicyReadFailureIsUnavailableAndWritesNothing(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	before := countKeys(t, r.s)
	fs := &getFailStorage{Storage: r.s, fail: true}
	status, body := r.e.Serve(context.Background(), fs, alice, decideFrame(runID, tok, "d1", "c1"))
	if status != 200 || code(mustParse(t, body)) != CodeUnavailable {
		t.Fatalf("read failure: status %d body %s", status, body)
	}
	if after := countKeys(t, r.s); after != before {
		t.Fatalf("a refused decide wrote %d records", after-before)
	}
	fs.fail = false
	if m := r.call(alice, decideFrame(runID, tok, "d1", "c1")); m["decision"] != "deny" {
		t.Fatalf("healthy retry did not answer: %v", m)
	}
}

func mustParse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func countKeys(t *testing.T, s logical.Storage) int {
	t.Helper()
	keys, err := s.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}
