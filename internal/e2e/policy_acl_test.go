package e2e

import "testing"

// The stored allow list is written by an operator and read only through Bao's ACL.
// Its own server, so the allow it stores cannot change the shared identity tests.
func TestPolicyACLAndStoredAllow(t *testing.T) {
	s := start(t)
	alice, _ := s.login(t, "alice")

	if st, m := s.do(t, "GET", "/v1/tracekit/policy", alice, nil); st != 403 {
		t.Errorf("agent GET policy: %d %v, want 403", st, m)
	}
	if st, m := s.do(t, "POST", "/v1/tracekit/policy", alice, map[string]any{"allow": []string{"bash"}}); st != 403 {
		t.Errorf("agent POST policy: %d %v, want 403", st, m)
	}
	if st, m := s.do(t, "POST", "/v1/tracekit/policy", rootToken, map[string]any{}); st != 400 {
		t.Errorf("write without allow: %d %v, want 400", st, m)
	}
	if st, m := s.do(t, "POST", "/v1/tracekit/policy", rootToken, map[string]any{"allow": []string{"bash"}}); st >= 300 {
		t.Fatalf("operator write: %d %v", st, m)
	}
	st, m := s.do(t, "GET", "/v1/tracekit/policy", rootToken, nil)
	data, _ := m["data"].(map[string]any)
	allow, _ := data["allow"].([]any)
	if st != 200 || len(allow) != 1 || allow[0] != "bash" {
		t.Fatalf("operator read: %d %v", st, m)
	}

	reg := register(t, s, alice, "acl-1", "")
	runID, runTok := reg["run_id"].(string), reg["run_token"].(string)
	d := decide(t, s, alice, "acl-2", runID, runTok, "c1")
	if code(d) != "" || d["decision"] != "allow" || !hasRule(d, "TK-STORED-ALLOW") {
		t.Errorf("listed tool: %v", d)
	}
	rm := s.rpc(t, alice, `{"method":"decide","request_id":"acl-3","run_id":"`+runID+`","run_token":"`+runTok+
		`","stream":"s","client_seq":1,"tool_call_id":"c2","tool":"rm","args_source":"parsed","args":{"p":"/"}}`)
	if code(rm) != "" || rm["decision"] != "deny" {
		t.Errorf("unlisted tool: %v", rm)
	}
}

func hasRule(m map[string]any, rule string) bool {
	rs, _ := m["rule_ids"].([]any)
	for _, r := range rs {
		if r == rule {
			return true
		}
	}
	return false
}
