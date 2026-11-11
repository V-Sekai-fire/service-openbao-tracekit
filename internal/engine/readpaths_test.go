package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/bundle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/checkpoint"
)

// readPath reads a path through the framework backend, as Bao would route it.
func readPath(t *testing.T, r *rig, path string) *logical.Response {
	t.Helper()
	b, err := r.e.Backend(context.Background(), logical.TestBackendConfig())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.ReadOperation, Path: path, Storage: r.s})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The export endpoint returns exactly the bytes of bundle.Write(Export(...)).
func TestExportEndpointReturnsTheExportBytes(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m := r.call(alice, closeFrame(runID, tok, "c")); code(m) != "" {
		t.Fatalf("close_run refused: %v", m)
	}
	resp := readPath(t, r, "runs/default/"+runID+"/export")
	if resp.Data[logical.HTTPStatusCode] != http.StatusOK {
		t.Fatalf("status %v", resp.Data[logical.HTTPStatusCode])
	}
	if resp.Data[logical.HTTPContentType] != "application/zip" {
		t.Fatalf("content type %v", resp.Data[logical.HTTPContentType])
	}
	files, err := r.e.Export(context.Background(), r.s, "default", runID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := bundle.Write(files)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(resp.Data[logical.HTTPRawBody].(string)), want) {
		t.Fatal("the endpoint's bytes differ from bundle.Write(Export)")
	}
}

// An open run is refused: 409 with an error frame, and no zip.
func TestExportEndpointRefusesOpenRun(t *testing.T) {
	r := newRig(t)
	runID, _ := r.register(alice, "r1")
	resp := readPath(t, r, "runs/default/"+runID+"/export")
	if resp.Data[logical.HTTPStatusCode] != http.StatusConflict {
		t.Fatalf("open run: status %v, want 409", resp.Data[logical.HTTPStatusCode])
	}
	if bytes.HasPrefix([]byte(resp.Data[logical.HTTPRawBody].(string)), []byte("PK")) {
		t.Fatal("an open run returned a zip")
	}
}

// The trust endpoint returns the log's public key only, and it is the key the export is signed with.
func TestTrustEndpointPinsTheLogKey(t *testing.T) {
	r := newRig(t)
	r.register(alice, "r1")
	resp := readPath(t, r, "trust")
	if resp.Data[logical.HTTPStatusCode] != http.StatusOK {
		t.Fatalf("status %v", resp.Data[logical.HTTPStatusCode])
	}
	var tr map[string]any
	if err := json.Unmarshal([]byte(resp.Data[logical.HTTPRawBody].(string)), &tr); err != nil {
		t.Fatal(err)
	}
	want, err := checkpoint.VKey(r.e.LogOrigin(), checkpoint.TypeEd25519, r.e.LogPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	logs, _ := tr["logs"].([]any)
	if len(logs) != 1 || logs[0] != want {
		t.Fatalf("logs %v, want [%s]", logs, want)
	}
	if len(tr) != 3 {
		t.Fatalf("trust has keys %v: only logs, algs and witnesses_required are allowed", tr)
	}
}
