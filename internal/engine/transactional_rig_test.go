package engine

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// The test rig's storage must support interactive transactions: the engine's per-request
// writes depend on them, and a rig without them would pass tests the real backend fails.
func TestRigStorageIsTransactional(t *testing.T) {
	r := newRig(t)
	if _, ok := r.s.(logical.TransactionalStorage); !ok {
		t.Fatalf("rig storage %T has no BeginTx", r.s)
	}
	tx, err := r.s.(logical.TransactionalStorage).BeginTx(t.Context())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
}
