package engine

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/bundle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/checkpoint"
)

// rawReply answers with exact bytes through HTTPRawBody (memory #751: those leave byte-exact).
func rawReply(status int, ctype string, body []byte) *logical.Response {
	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: ctype,
		logical.HTTPStatusCode:  status,
		logical.HTTPRawBody:     string(body),
	}}
}

// exportPath serves one run as a .tkb: runs/<tenant>/<run_id>/export. Bao's ACL decides who may
// read it; the agent's token is given only the rpc path.
func (e *Engine) exportPath() *framework.Path {
	return &framework.Path{
		Pattern: "runs/" + framework.GenericNameRegex("tenant") + "/" + framework.GenericNameRegex("run_id") + "/export",
		Fields: map[string]*framework.FieldSchema{
			"tenant": {Type: framework.TypeString},
			"run_id": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: e.pathExport},
		},
	}
}

// pathExport answers 200 with the zip, or 409 with an error frame when Export refuses (an open
// run, an unknown run, or a storage error: all export errors are 409 for now).
func (e *Engine) pathExport(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	files, err := e.Export(ctx, req.Storage, d.Get("tenant").(string), d.Get("run_id").(string))
	if err != nil {
		return rawReply(http.StatusConflict, "application/json", errorFrame(CodeInvalidRequest, err.Error())), nil
	}
	zipped, err := bundle.Write(files)
	if err != nil {
		return rawReply(http.StatusInternalServerError, "application/json", errorFrame(CodeInvalidRequest, err.Error())), nil
	}
	return rawReply(http.StatusOK, "application/zip", zipped), nil
}

// trustPath serves the public trust config a verifier pins: trust.
func (e *Engine) trustPath() *framework.Path {
	return &framework.Path{
		Pattern: "trust",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: e.pathTrust},
		},
	}
}

// pathTrust returns only the log's public verification key, never LogSeed or any other secret.
func (e *Engine) pathTrust(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensure(ctx, req.Storage); err != nil {
		e.loaded = false
		return rawReply(http.StatusServiceUnavailable, "application/json", errorFrame(CodeUnavailable, "the signer log cannot be read")), nil
	}
	vk, err := checkpoint.VKey(e.LogOrigin(), checkpoint.TypeEd25519, e.LogPublicKey())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{"logs": []string{vk}, "algs": []string{"ed25519"}, "witnesses_required": 0})
	if err != nil {
		return nil, err
	}
	return rawReply(http.StatusOK, "application/json", body), nil
}
