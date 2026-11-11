package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// policy.decision carries policy_hash: "sha256:" + SHA-256 of the JCS of the stored policy.
func TestDecisionCarriesPolicyHash(t *testing.T) {
	r := newRig(t)
	if err := r.s.Put(context.Background(), &logical.StorageEntry{Key: policyKey, Value: []byte(`{"allow":["bash"]}`)}); err != nil {
		t.Fatal(err)
	}
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	want := jcs.SHA256Hex(mustCanonical(map[string]any{"allow": []any{"bash"}}))
	if got := decisionPolicyHash(t, r.s); got != want {
		t.Fatalf("policy_hash %q, want %q", got, want)
	}
}

// decisionPolicyHash reads policy_hash from the first policy.decision record.
func decisionPolicyHash(t *testing.T, s logical.Storage) string {
	t.Helper()
	keys, err := s.List(context.Background(), "records/")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		raw, err := s.Get(context.Background(), "records/"+k)
		if err != nil || raw == nil {
			t.Fatalf("%s: %v", k, err)
		}
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			t.Fatal(err)
		}
		if en.Type != "policy.decision" {
			continue
		}
		v, err := jcs.Parse([]byte(en.Record))
		if err != nil {
			t.Fatal(err)
		}
		ev := v.(map[string]any)["event"].(map[string]any)
		h, _ := ev["data"].(map[string]any)["policy_hash"].(string)
		return h
	}
	t.Fatal("no policy.decision record")
	return ""
}
