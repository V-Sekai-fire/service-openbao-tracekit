package engine

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// policyKey is the storage key of the operator's allow list. It is written only
// through the policy path, which Bao's ACL guards; the frame cannot reach it.
const policyKey = "policy"

// StoredPolicy is the allow list an operator writes: every tool not named is denied.
type StoredPolicy struct {
	Allow []string `json:"allow"`
}

// invalidPolicy is what a stored policy that cannot be parsed becomes: deny everything.
func invalidPolicy(string) (string, []string) { return "deny", []string{"TK-POLICY-INVALID"} }

// policyFor returns the policy for one decide. A stored policy wins; with none stored,
// the engine's own Policy applies (DenyAll by default). A storage read error is returned
// so the caller refuses the call rather than guessing.
func (e *Engine) policyFor(ctx context.Context, s logical.Storage) (Policy, error) {
	ent, err := s.Get(ctx, policyKey)
	if err != nil {
		return nil, err
	}
	if ent == nil {
		return e.Policy, nil
	}
	var p StoredPolicy
	dec := json.NewDecoder(bytes.NewReader(ent.Value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return invalidPolicy, nil
	}
	allowed := make(map[string]bool, len(p.Allow))
	for _, t := range p.Allow {
		allowed[t] = true
	}
	return func(tool string) (string, []string) {
		if allowed[tool] {
			return "allow", []string{"TK-STORED-ALLOW"}
		}
		return "deny", []string{"TK-STORED-DENY"}
	}, nil
}

// policyPath is the operator's path to write and read the allow list.
func (e *Engine) policyPath() *framework.Path {
	return &framework.Path{
		Pattern: "policy",
		Fields: map[string]*framework.FieldSchema{
			"allow": {Type: framework.TypeStringSlice,
				Description: "Tool names this policy allows. Every other tool is denied."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: e.pathPolicyWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: e.pathPolicyRead},
		},
	}
}

func (e *Engine) pathPolicyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b, err := json.Marshal(StoredPolicy{Allow: d.Get("allow").([]string)})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: policyKey, Value: b}); err != nil {
		return nil, err
	}
	return nil, nil
}

func (e *Engine) pathPolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	ent, err := req.Storage.Get(ctx, policyKey)
	if err != nil {
		return nil, err
	}
	if ent == nil {
		return nil, nil
	}
	var p StoredPolicy
	if err := json.Unmarshal(ent.Value, &p); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{"allow": p.Allow}}, nil
}
