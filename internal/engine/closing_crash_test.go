package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// failOn fails the first Put whose value contains needle, once, when armed.
type failOn struct {
	logical.Storage
	needle string
	armed  bool
}

func (f *failOn) Put(ctx context.Context, e *logical.StorageEntry) error {
	if f.armed && strings.Contains(string(e.Value), f.needle) {
		f.armed = false
		return context.DeadlineExceeded
	}
	return f.Storage.Put(ctx, e)
}

// A crash between run.closing and run.final: the run refuses writes while closing,
// and a retry writes only run.final, with the head fixed.
func TestCloseCrashBetweenClosingAndFinal(t *testing.T) {
	s := &failOn{Storage: newRig(t).s, needle: `"type":"run.final"`}
	r := &rig{t: t, e: NewEngine(), s: s}
	runID, tok := r.register(alice, "r1")
	r.call(alice, decideFrame(runID, tok, "d1", "c1"))
	s.armed = true
	if m := r.call(alice, closeFrame(runID, tok, "c")); code(m) == "" {
		t.Fatal("close succeeded although run.final could not be written")
	}
	if m := r.call(alice, decideFrame(runID, tok, "d2", "c2")); code(m) == "" {
		t.Fatalf("decide accepted while the run is closing: %v", m)
	}
	if m := r.call(alice, closeFrame(runID, tok, "c")); code(m) != "" {
		t.Fatalf("retry refused: %v", m)
	}
	count := map[string]int{}
	for _, en := range entriesOf(t, s) {
		count[en.Type]++
	}
	if count["run.closing"] != 1 || count["run.final"] != 1 {
		t.Fatalf("records after retry: %v", count)
	}
	checkHead(t, entriesOf(t, s))
}

// failOn transactions: the needle is checked on the Put inside the transaction.
func (f *failOn) BeginTx(ctx context.Context) (logical.Transaction, error) {
	tx, err := f.Storage.(logical.TransactionalStorage).BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &failOnTx{Transaction: tx, f: f}, nil
}

func (f *failOn) BeginReadOnlyTx(ctx context.Context) (logical.Transaction, error) {
	return f.Storage.(logical.TransactionalStorage).BeginReadOnlyTx(ctx)
}

type failOnTx struct {
	logical.Transaction
	f *failOn
}

func (t *failOnTx) Put(ctx context.Context, e *logical.StorageEntry) error {
	if t.f.armed && strings.Contains(string(e.Value), t.f.needle) {
		t.f.armed = false
		return context.DeadlineExceeded
	}
	return t.Transaction.Put(ctx, e)
}
