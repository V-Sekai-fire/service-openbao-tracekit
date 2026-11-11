package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// entriesOf returns the stored records in log order.
func entriesOf(t *testing.T, s logical.Storage) []entry {
	t.Helper()
	keys, err := s.List(context.Background(), "records/")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]entry, 0, len(keys))
	for i := range keys {
		raw, err := s.Get(context.Background(), fmt.Sprintf("records/%020d", i))
		if err != nil || raw == nil {
			t.Fatalf("record %d: %v", i, err)
		}
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			t.Fatal(err)
		}
		out = append(out, en)
	}
	return out
}

// closeFrame is a close_run request for runID.
func closeFrame(runID, tok, reqID string) string {
	return `{"method":"close_run","request_id":"` + reqID + `","run_id":"` + runID + `","run_token":"` + tok + `","reason":"done"}`
}

// checkHead asserts run.final's head names the run.closing record: its hash and its run_seq.
func checkHead(t *testing.T, es []entry) {
	t.Helper()
	var closing, final *entry
	for i := range es {
		switch es[i].Type {
		case "run.closing":
			closing = &es[i]
		case "run.final":
			final = &es[i]
		}
	}
	if closing == nil || final == nil {
		t.Fatal("missing run.closing or run.final")
	}
	v, err := jcs.Parse([]byte(final.Record))
	if err != nil {
		t.Fatal(err)
	}
	data := v.(map[string]any)["event"].(map[string]any)["data"].(map[string]any)
	if got := fmt.Sprint(data["head_hash"]); got != closing.Hash {
		t.Errorf("head_hash %s is not the run.closing hash %s", got, closing.Hash)
	}
	if got := fmt.Sprint(data["head_run_seq"]); got != fmt.Sprint(closing.RunSeq) {
		t.Errorf("head_run_seq %s is not the run.closing run_seq %d", got, closing.RunSeq)
	}
}

// run.final's head must name the record before it: the run.closing.
func TestCloseHeadNamesRunClosing(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m := r.call(alice, closeFrame(runID, tok, "c")); code(m) != "" {
		t.Fatalf("close_run refused: %v", m)
	}
	checkHead(t, entriesOf(t, r.s))
}
