package engine

import "testing"

func consumeFrame(runID, tok, call, tool, rawArgs string) string {
	return `{"method":"approval_consume","request_id":"cons-` + call + `-` + tool + `-` + rawArgs +
		`","run_id":"` + runID + `","run_token":"` + tok + `","tool_call_id":"` + call +
		`","tool":"` + tool + `","args_source":"raw","args":"` + rawArgs + `"}`
}

func consumeRule(m map[string]any) string {
	rs, _ := m["rule_ids"].([]any)
	if len(rs) == 0 {
		return ""
	}
	s, _ := rs[0].(string)
	return s
}

func allowBash(r *rig) {
	r.e.Policy = func(string) (string, []string) { return "allow", []string{"T"} }
}

func TestConsumeAllowedCallIsOK(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	m := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if m["ok"] != true || code(m) != "" {
		t.Fatalf("allowed call not consumed: %v", m)
	}
}

func TestConsumeDeniedCallIsRefused(t *testing.T) {
	r := newRig(t) // DenyAll
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	m := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if m["ok"] != false || consumeRule(m) != "TK-APPROVAL-REQUIRED" {
		t.Fatalf("denied call consumed: %v", m)
	}
}

func TestConsumeUnknownCallIsRefused(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, consumeFrame(runID, tok, "never-decided", "bash", "{}"))
	if m["ok"] != false || consumeRule(m) != "TK-APPROVAL-REQUIRED" {
		t.Fatalf("unknown call consumed: %v", m)
	}
}

func TestConsumeWithChangedArgsIsMismatch(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	m := r.call(alice, consumeFrame(runID, tok, "c1", "bash", `{\"x\":1}`))
	if m["ok"] != false || consumeRule(m) != "TK-APPROVAL-MISMATCH" {
		t.Fatalf("changed args consumed: %v", m)
	}
}

func TestConsumeByAnotherPrincipalIsRefused(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	m := r.call(bob, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if code(m) != CodeRunToken {
		t.Fatalf("bob consumed alice's call: %v", m)
	}
}

func TestConsumeOnClosedRunIsRefused(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	r.call(alice, `{"method":"close_run","request_id":"c","run_id":"`+runID+`","run_token":"`+tok+`"}`)
	m := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if code(m) != CodeInvalidRequest {
		t.Fatalf("closed run consumed: %v", m)
	}
}

// Consume records nothing: storage is unchanged, and a replay gives the same answer.
func TestConsumeWritesNothing(t *testing.T) {
	r := newRig(t)
	allowBash(r)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	before := countRecords(t, r.s)
	a := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	b := r.call(alice, consumeFrame(runID, tok, "c1", "bash", "{}"))
	if after := countRecords(t, r.s); after != before {
		t.Fatalf("consume wrote %d records", after-before)
	}
	if a["ok"] != true || b["ok"] != true {
		t.Fatalf("replay answers differ: %v %v", a, b)
	}
}
