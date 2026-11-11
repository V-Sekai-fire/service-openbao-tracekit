package engine

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

func TestHello(t *testing.T) {
	status, body := Handle(`{"method":"hello"}`)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	want := `{"pid":` + strconv.Itoa(os.Getpid()) + `,"proto":[15,19],"version":"1.4.2"}`
	if string(body) != want {
		t.Fatalf("got %s want %s", body, want)
	}
}

// Frames upstream's strict parser refuses are refused here as invalid_request,
// each as a 200 error frame.
func TestStrictRefusals(t *testing.T) {
	cases := map[string]string{
		"duplicate key":   `{"method":"hello","method":"hello"}`,
		"lone surrogate":  `{"method":"hello","s":"\ud800"}`,
		"unsafe integer":  `{"method":"hello","n":9007199254740993}`,
		"non-finite":      `{"method":"hello","n":1e999}`,
		"not an object":   `[1,2]`,
		"empty":           ``,
		"trailing text":   `{"method":"hello"} x`,
		"unknown method":  `{"method":"decide"}`,
		"missing method":  `{}`,
		"method not text": `{"method":1}`,
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			status, body := Handle(frame)
			if status != 200 {
				t.Fatalf("status %d", status)
			}
			v, err := jcs.Parse(body)
			if err != nil {
				t.Fatalf("reply is not strict JSON: %v", err)
			}
			e, ok := v.(map[string]any)["error"].(map[string]any)
			if !ok || e["code"] != CodeInvalidRequest {
				t.Fatalf("not an invalid_request error frame: %s", body)
			}
			if _, has := v.(map[string]any)["proto"]; has {
				t.Fatalf("refusal looks like a hello: %s", body)
			}
		})
	}
}

func TestOversize(t *testing.T) {
	status, body := Handle(strings.Repeat("a", MaxLine+1))
	if status != 413 || !strings.Contains(string(body), CodeQuotaExceeded) {
		t.Fatalf("status %d body %s", status, body)
	}
}

func backend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	return b, conf.StorageView
}

func call(t *testing.T, b logical.Backend, s logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "rpc", Data: data, Storage: s,
	})
}

// Through the real backend: the reply goes out as a raw body, byte for byte.
func TestBackendHello(t *testing.T) {
	b, s := backend(t)
	resp, err := call(t, b, s, map[string]any{"frame": `{"method":"hello"}`})
	if err != nil || resp == nil {
		t.Fatalf("resp %v err %v", resp, err)
	}
	if resp.Data[logical.HTTPContentType] != "application/json" || resp.Data[logical.HTTPStatusCode] != 200 {
		t.Fatalf("headers %v", resp.Data)
	}
	raw, _ := resp.Data[logical.HTTPRawBody].(string)
	_, want := Handle(`{"method":"hello"}`)
	if raw != string(want) {
		t.Fatalf("raw body %q want %q", raw, want)
	}
}

// A request with no frame, or a non-string frame, is an error: no frame is returned.
func TestBackendFailsClosed(t *testing.T) {
	b, s := backend(t)
	for name, data := range map[string]map[string]any{
		"no frame":  {},
		"wrong key": {"other": `{"method":"hello"}`},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := call(t, b, s, data)
			if err == nil && (resp == nil || resp.Data[logical.HTTPRawBody] != nil) {
				t.Fatalf("answered without a frame: %v", resp)
			}
		})
	}
}

// Reads and deletes of the rpc path are not supported.
func TestOnlyUpdate(t *testing.T) {
	b, s := backend(t)
	for _, op := range []logical.Operation{logical.ReadOperation, logical.DeleteOperation, logical.ListOperation} {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: "rpc", Storage: s})
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Errorf("%s answered: %v", op, resp)
		}
	}
}
