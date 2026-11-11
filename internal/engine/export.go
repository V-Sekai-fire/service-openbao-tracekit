package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/bundle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/merkle"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/record"
)

// Export builds the files of a format v2 bundle for one closed run: its records in
// log order, the signer's key records, inclusion proofs over the whole log for the
// run's first and last records and every key record, and a checkpoint signed by the
// log key. A run without run.final is refused. The log key never leaves the engine.
func (e *Engine) Export(ctx context.Context, s logical.Storage, tenant, runID string) ([]bundle.File, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensure(ctx, s); err != nil {
		e.loaded = false
		return nil, err
	}
	r := e.runs[tenant+"\x00"+runID]
	if r == nil || !r.closed {
		return nil, fmt.Errorf("run %s/%s has no run.final: only closed runs are exported", tenant, runID)
	}
	n := e.nextSeq
	leaves := make([]merkle.Hash, n)
	entries := make([]entry, n)
	for i := 0; i < n; i++ {
		raw, err := s.Get(ctx, fmt.Sprintf("records/%020d", i))
		if err != nil || raw == nil {
			return nil, fmt.Errorf("record %d unreadable", i)
		}
		var en entry
		if err := json.Unmarshal(raw.Value, &en); err != nil {
			return nil, err
		}
		data, err := record.LeafData(en.Hash)
		if err != nil {
			return nil, err
		}
		entries[i], leaves[i] = en, merkle.LeafHash(data)
	}
	var runLines, keyLines []string
	want := map[int]bool{}
	first, last := -1, -1
	for _, en := range entries {
		switch {
		case en.Tenant == tenant && en.RunID == runID:
			runLines = append(runLines, en.Record)
			if first < 0 {
				first = en.Seq
			}
			last = en.Seq
		case en.Type == "signer.epoch" || en.Type == "key.retire":
			keyLines = append(keyLines, en.Record)
			want[en.Seq] = true
		}
	}
	if len(runLines) == 0 {
		return nil, fmt.Errorf("run %s/%s has no records", tenant, runID)
	}
	want[first], want[last] = true, true
	indices := make([]int, 0, len(want))
	for i := range want {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	proofs, err := bundle.Proofs(leaves, indices)
	if err != nil {
		return nil, err
	}
	inclusion := make(map[string][]string, len(proofs))
	for i, p := range proofs {
		inclusion[strconv.Itoa(i)] = p
	}
	origin := e.LogOrigin()
	cpName := "checkpoints/" + strconv.Itoa(n) + ".note"
	note, err := bundle.Note(origin, uint64(n), merkle.Root(leaves), origin, ed25519.NewKeyFromSeed(e.cfg.LogSeed))
	if err != nil {
		return nil, err
	}
	pj, err := json.Marshal(map[string]any{"checkpoint": cpName, "tree_size": n, "inclusion": inclusion})
	if err != nil {
		return nil, err
	}
	extra := []bundle.File{{Name: cpName, Data: []byte(note)}, {Name: "proofs/records.json", Data: pj}}
	return bundle.AssembleWith(map[string][]string{bundle.RunFile(tenant, runID): runLines}, keyLines, extra)
}
