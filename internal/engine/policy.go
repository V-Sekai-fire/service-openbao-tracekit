package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
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

// parseStored accepts exactly {"allow": [non-empty strings]}, parsed strictly.
// Duplicate keys, trailing data, extra keys and any other shape are errors.
func parseStored(b []byte) ([]string, error) {
	v, err := jcs.Parse(b)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 1 {
		return nil, fmt.Errorf("policy must be an object with only the key allow")
	}
	arr, ok := obj["allow"].([]any)
	if !ok {
		return nil, fmt.Errorf("allow must be an array")
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("allow entries must be non-empty strings")
		}
		out = append(out, s)
	}
	return out, nil
}

// policyFor returns the policy for one decide. A stored policy wins; with none stored,
// the engine's own Policy applies (DenyAll by default). A storage read error is returned
// so the caller refuses the call rather than guessing. A stored value that does not
// parse as the one shape is TK-POLICY-INVALID, which denies.
func (e *Engine) policyFor(ctx context.Context, s logical.Storage) (Policy, error) {
	ent, err := s.Get(ctx, policyKey)
	if err != nil {
		return nil, err
	}
	if ent == nil {
		return e.Policy, nil
	}
	list, err := parseStored(ent.Value)
	if err != nil {
		return invalidPolicy, nil
	}
	allowed := make(map[string]bool, len(list))
	for _, t := range list {
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
	// A write without allow is refused: a typo'd field must not store deny-all silently.
	if _, ok := d.GetOk("allow"); !ok {
		return nil, logical.ErrInvalidRequest
	}
	allow, _ := d.Get("allow").([]string)
	if allow == nil {
		allow = []string{}
	}
	for _, t := range allow {
		if t == "" {
			return nil, logical.ErrInvalidRequest
		}
	}
	b, err := json.Marshal(StoredPolicy{Allow: allow})
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
	list, err := parseStored(ent.Value)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	return &logical.Response{Data: map[string]interface{}{"allow": list}}, nil
}
