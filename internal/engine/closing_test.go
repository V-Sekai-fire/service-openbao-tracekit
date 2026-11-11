package engine

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// recordTypes returns the record types in log order.
func recordTypes(t *testing.T, s logical.Storage) []string {
	t.Helper()
	keys, err := s.List(context.Background(), "records/")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		raw, err := s.Get(context.Background(), "records/"+k)
		if err != nil || raw == nil {
			t.Fatalf("%s: %v", k, err)
		}
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			t.Fatal(err)
		}
		out = append(out, en.Type)
	}
	return out
}

// close_run writes run.closing and then run.final, in that order, as upstream does.
func TestCloseWritesClosingBeforeFinal(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, `{"method":"close_run","request_id":"c","run_id":"`+runID+`","run_token":"`+tok+`","reason":"done"}`)
	if code(m) != "" {
		t.Fatalf("close_run refused: %v", m)
	}
	types := recordTypes(t, r.s)
	ci, fi := -1, -1
	for i, ty := range types {
		switch ty {
		case "run.closing":
			ci = i
		case "run.final":
			fi = i
		}
	}
	if ci < 0 || fi < 0 || ci >= fi || fi != len(types)-1 {
		t.Fatalf("want run.closing then run.final last, got %v", types)
	}
}
