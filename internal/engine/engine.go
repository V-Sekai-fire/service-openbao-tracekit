// Package engine is the OpenBao secrets engine that speaks Tracekit's signer RPC.
//
// The one write path, rpc, takes the whole frame as a single string field so Bao's
// JSON decode cannot change its bytes (see docs/shim.md). The frame is parsed
// strictly through internal/jcs, answered through HTTPRawBody, and refused
// closed: anything the engine cannot answer becomes an error frame or a non-200,
// never an allow-shaped body.
//
// Implemented: hello (stateless), register_run, decide, complete, close_run.
// The default policy denies every tool call. Identity is the Bao entity ID.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

// Pinned to Tracekit tag v1.4.2 (tracekit-ai >=1.4.2,<1.5): RPC_MIN 15, RPC_VERSION 19.
const (
	RPCMin     = 15
	RPCVersion = 19
	Version    = "1.4.2"
	// MaxLine is upstream's MAX_LINE: bytes of one transport frame.
	MaxLine = 1 << 20
)

// Error codes used so far (a subset of upstream ERROR_CODES).
const (
	CodeInvalidRequest = "invalid_request"
	CodeQuotaExceeded  = "quota_exceeded"
	CodeForbidden      = "forbidden"
)

// parseFrame strictly parses a frame. On failure obj is nil and body is the reply.
func parseFrame(frame string) (int, map[string]any, []byte) {
	if len(frame) > MaxLine {
		return http.StatusRequestEntityTooLarge, nil, errorFrame(CodeQuotaExceeded,
			fmt.Sprintf("body longer than %d bytes", MaxLine))
	}
	v, err := jcs.Parse([]byte(frame))
	if err != nil {
		return http.StatusOK, nil, errorFrame(CodeInvalidRequest, err.Error())
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return http.StatusOK, nil, errorFrame(CodeInvalidRequest, "a frame must be a JSON object")
	}
	return http.StatusOK, obj, nil
}

// stateless answers the methods that need no state: hello, else a refusal.
func stateless(obj map[string]any) []byte {
	if m, _ := obj["method"].(string); m == "hello" {
		return mustCanonical(map[string]any{
			"proto":   []any{json.Number(fmt.Sprint(RPCMin)), json.Number(fmt.Sprint(RPCVersion))},
			"version": Version,
			"pid":     json.Number(fmt.Sprint(os.Getpid())),
		})
	}
	return errorFrame(CodeInvalidRequest, "unknown or unsupported method")
}

// Handle answers one frame without state: hello, and refusals for the rest.
func Handle(frame string) (int, []byte) {
	status, obj, body := parseFrame(frame)
	if obj == nil {
		return status, body
	}
	return http.StatusOK, stateless(obj)
}

func errorFrame(code, msg string) []byte {
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	return mustCanonical(map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

// mustCanonical canonicalises a value built here from strict-JSON types. A failure
// is a programming error, so it panics rather than return an unsigned-looking body.
func mustCanonical(v any) []byte {
	b, err := jcs.Canonical(v)
	if err != nil {
		panic("engine: cannot canonicalise own reply: " + err.Error())
	}
	return b
}

// Factory builds the backend for Bao's plugin machinery, with a default-deny engine.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return NewEngine().Backend(ctx, conf)
}

// Backend wires this engine into a framework backend.
func (e *Engine) Backend(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Tracekit signer RPC over one string field.",
		Paths: []*framework.Path{{
			Pattern: "rpc",
			Fields: map[string]*framework.FieldSchema{
				"frame": {Type: framework.TypeString, Description: "One Tracekit RPC frame, as JSON text."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: e.pathRPC},
			},
		}},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *Engine) pathRPC(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	raw, ok := d.GetOk("frame")
	if !ok {
		return nil, logical.ErrInvalidRequest // non-200: no frame
	}
	frame, ok := raw.(string)
	if !ok {
		return nil, logical.ErrInvalidRequest
	}
	// Identity comes from Bao, never from the frame. A plain token has no entity: refused.
	var id *Identity
	if req.EntityID != "" {
		id = &Identity{Scheme: "bao-entity", Subject: req.EntityID}
	}
	status, body := e.Serve(ctx, req.Storage, id, frame)
	return &logical.Response{Data: map[string]interface{}{
		logical.HTTPContentType: "application/json",
		logical.HTTPStatusCode:  status,
		logical.HTTPRawBody:     string(body),
	}}, nil
}
