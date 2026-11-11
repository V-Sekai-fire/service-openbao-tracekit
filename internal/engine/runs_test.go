package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
)

type rig struct {
	t *testing.T
	e *Engine
	s logical.Storage
}

func newRig(t *testing.T) *rig {
	return &rig{t: t, e: NewEngine(), s: &logical.InmemStorage{}}
}

var alice = &Identity{Scheme: "bao-entity", Subject: "entity-alice"}
var bob = &Identity{Scheme: "bao-entity", Subject: "entity-bob"}

func (r *rig) call(id *Identity, frame string) map[string]any {
	r.t.Helper()
	status, body := r.e.Serve(context.Background(), r.s, id, frame)
	if status != 200 {
		r.t.Fatalf("status %d: %s", status, body)
	}
	v, err := jcs.Parse(body)
	if err != nil {
		r.t.Fatalf("reply is not strict JSON: %v: %s", err, body)
	}
	return v.(map[string]any)
}

func code(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (r *rig) register(id *Identity, reqID string) (runID, tok string) {
	r.t.Helper()
	m := r.call(id, `{"method":"register_run","request_id":"`+reqID+`","agent":"hermes"}`)
	if code(m) != "" {
		r.t.Fatalf("register_run refused: %v", m)
	}
	return m["run_id"].(string), m["run_token"].(string)
}

func decideFrame(runID, tok, reqID, call string) string {
	return `{"method":"decide","request_id":"` + reqID + `","run_id":"` + runID + `","run_token":"` + tok +
		`","stream":"s","client_seq":0,"tool_call_id":"` + call + `","tool":"bash","args_source":"raw","args":"{}"}`
}

func TestNoIdentityIsRefused(t *testing.T) {
	r := newRig(t)
	for _, m := range []string{"register_run", "decide", "complete", "close_run"} {
		got := r.call(nil, `{"method":"`+m+`","request_id":"x"}`)
		if code(got) != CodeUnauthenticated {
			t.Errorf("%s with no identity: %v", m, got)
		}
	}
	if r.e.loaded {
		t.Error("the log was opened for an unauthenticated caller")
	}
}

func TestFrameCannotNameItsOwnIdentity(t *testing.T) {
	r := newRig(t)
	for _, m := range []string{"register_run", "decide", "complete", "close_run"} {
		for _, f := range []string{`"caller":"gateway:x"`, `"principal":"person:eve"`, `"principal_token":"abc"`} {
			got := r.call(alice, `{"method":"`+m+`","request_id":"x",`+f+`}`)
			if code(got) != CodeForbidden {
				t.Errorf("%s with %s: %v", m, f, got)
			}
		}
	}
	if r.e.nextSeq != 0 {
		t.Error("a refused frame wrote a record")
	}
}

func TestDefaultPolicyDeniesEverything(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	if m["decision"] != "deny" {
		t.Fatalf("default policy did not deny: %v", m)
	}
}

func TestPolicyNeverAllowsOnAskOrUnknown(t *testing.T) {
	for _, answer := range []string{"ask", "", "ALLOW", "allow "} {
		r := newRig(t)
		a := answer
		r.e.Policy = func(string) (string, []string) { return a, nil }
		runID, tok := r.register(alice, "r1")
		if m := r.call(alice, decideFrame(runID, tok, "d1", "c1")); m["decision"] != "deny" {
			t.Errorf("policy answer %q gave %v", a, m["decision"])
		}
	}
	r := newRig(t)
	r.e.Policy = func(string) (string, []string) { return "allow", []string{"TEST"} }
	runID, tok := r.register(alice, "r1")
	if m := r.call(alice, decideFrame(runID, tok, "d1", "c1")); m["decision"] != "allow" {
		t.Errorf("explicit allow lost: %v", m)
	}
}

func TestRunTokenBindsRunAndCaller(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	if got := r.call(bob, decideFrame(runID, tok, "d1", "c1")); code(got) != CodeRunToken {
		t.Errorf("another caller used alice's token: %v", got)
	}
	if got := r.call(alice, decideFrame(runID, tok+"0", "d2", "c1")); code(got) != CodeRunToken {
		t.Errorf("edited token accepted: %v", got)
	}
	if got := r.call(alice, decideFrame("run-other", tok, "d3", "c1")); code(got) != CodeRunToken {
		t.Errorf("token reused for another run: %v", got)
	}
}

func TestRetryReturnsOriginalAndConflictIsRefused(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	f := decideFrame(runID, tok, "d1", "c1")
	first := r.call(alice, f)
	n := r.e.nextSeq
	again := r.call(alice, f)
	if r.e.nextSeq != n {
		t.Error("a retry wrote a second record")
	}
	a, _ := jcs.Canonical(first)
	b, _ := jcs.Canonical(again)
	if string(a) != string(b) {
		t.Errorf("retry answered differently:\n%s\n%s", a, b)
	}
	other := strings.Replace(f, `"tool":"bash"`, `"tool":"rm"`, 1)
	if got := r.call(alice, other); code(got) != CodeConflict {
		t.Errorf("same request_id with another payload: %v", got)
	}
}

func TestCloseRunReplyMatchesSchema(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	m := r.call(alice, `{"method":"close_run","request_id":"c","run_id":"`+runID+`","run_token":"`+tok+`"}`)
	if m["state"] != "closing" {
		t.Fatalf("state %v, schema allows only closing or open", m["state"])
	}
	if got := r.call(alice, decideFrame(runID, tok, "d1", "c1")); code(got) == "" {
		t.Errorf("decide after close_run succeeded: %v", got)
	}
}

// A restart rebuilds the same state from the log alone.
func TestReloadFromLog(t *testing.T) {
	r := newRig(t)
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	want := r.e.nextSeq
	r2 := &rig{t: t, e: NewEngine(), s: r.s}
	got := r2.call(alice, decideFrame(runID, tok, "d2", "c2"))
	if code(got) != "" || r2.e.nextSeq != want+1 {
		t.Fatalf("after reload: %v nextSeq %d want %d", got, r2.e.nextSeq, want+1)
	}
}

// Storage that fails its Nth Put.
type flaky struct {
	logical.Storage
	puts, failAt int
}

func (f *flaky) Put(ctx context.Context, e *logical.StorageEntry) error {
	f.puts++
	if f.puts == f.failAt {
		return context.DeadlineExceeded
	}
	return f.Storage.Put(ctx, e)
}

// A failed write answers unavailable, leaves no gap, and the retry succeeds once.
func TestFailedWriteLeavesNoGap(t *testing.T) {
	for failAt := 1; failAt <= 6; failAt++ {
		f := &flaky{Storage: &logical.InmemStorage{}}
		r := &rig{t: t, e: NewEngine(), s: f}
		f.failAt = failAt
		frame := `{"method":"register_run","request_id":"r1","agent":"hermes","run_id":"run-1"}`
		var last map[string]any
		for try := 0; try < 3; try++ {
			last = r.call(alice, frame)
			if code(last) != CodeUnavailable {
				break
			}
		}
		if code(last) != "" || last["run_id"] != "run-1" {
			t.Fatalf("failAt %d: retry did not succeed: %v", failAt, last)
		}
		keys, _ := f.Storage.List(context.Background(), "records/")
		r3 := &rig{t: t, e: NewEngine(), s: f.Storage}
		if again := r3.call(alice, frame); again["run_id"] != "run-1" {
			t.Fatalf("failAt %d: reload lost the run: %v", failAt, again)
		}
		for i, k := range keys {
			if k != strings.Repeat("0", 20-len(itoa(i)))+itoa(i) {
				t.Fatalf("failAt %d: gap or stray key %q at %d", failAt, k, i)
			}
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
