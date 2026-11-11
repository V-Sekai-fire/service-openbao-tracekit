package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// The state layout is a fixed set of shards, each with a byte budget. A shard is
// read and written on every request. The budget keeps each value under FDB's ~100 KB
// value limit with margin.
const shardBudget = 90 << 10

// Caps the engine enforces: K runs, C calls per run, R ring entries, IDs up to 128 bytes.
const (
	capRuns  = 64
	capCalls = 8
	capRing  = 512
	idCap    = 128
)

// Ring entries and calls store only the fields a reply needs, never raw frame bytes.
type lCall struct {
	DecisionID string   `json:"d"`
	Decision   string   `json:"v"`
	RuleIDs    []string `json:"r"`
	ArgsDigest string   `json:"a"`
	Done       bool     `json:"f"`
}

type lRun struct {
	Tenant string  `json:"t"`
	RunID  string  `json:"i"`
	Agent  string  `json:"g"`
	Subj   string  `json:"s"`
	Head   string  `json:"h"`
	Seq    int     `json:"q"`
	Calls  []lCall `json:"c"`
}

type lReq struct {
	Key      string   `json:"k"`
	Payload  string   `json:"p"`
	Decision string   `json:"v"`
	DecID    string   `json:"d"`
	RuleIDs  []string `json:"r"`
	RunSeq   int      `json:"q"`
	At       int64    `json:"t"`
}

func TestStateWorstCaseFits(t *testing.T) {
	id := strings.Repeat("x", idCap)
	digest := "sha256:" + strings.Repeat("a", 64)
	rules := []string{strings.Repeat("R", idCap)}

	var runs []lRun
	for i := 0; i < capRuns; i++ {
		r := lRun{Tenant: id, RunID: id, Agent: id, Subj: id, Head: digest, Seq: 99999}
		for j := 0; j < capCalls; j++ {
			r.Calls = append(r.Calls, lCall{DecisionID: id, Decision: "deny", RuleIDs: rules, ArgsDigest: digest, Done: true})
		}
		runs = append(runs, r)
	}
	var reqs []lReq
	for i := 0; i < capRing; i++ {
		reqs = append(reqs, lReq{Key: digest, Payload: digest, Decision: "deny", DecID: id, RuleIDs: rules, RunSeq: 99999, At: 1 << 40})
	}

	// Shard the layout: state/meta holds the frontier and head; state/runs/<n> holds 8
	// runs; state/reqs/<n> holds 64 ring entries. Measure each shard as encoded.
	size := func(v any) int {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	frontier := make([]string, 64)
	for i := range frontier {
		frontier[i] = digest
	}
	worst := size(map[string]any{"frontier": frontier, "head": digest, "next_seq": 99999})
	for i := 0; i < capRuns; i += 8 {
		if n := size(runs[i : i+8]); n > worst {
			worst = n
		}
	}
	for i := 0; i < capRing; i += 64 {
		if n := size(reqs[i : i+64]); n > worst {
			worst = n
		}
	}
	t.Logf("largest shard: %d bytes (budget %d)", worst, shardBudget)
	if worst > shardBudget {
		t.Fatalf("largest shard %d bytes exceeds budget %d", worst, shardBudget)
	}
	t.Logf("single-value layout would be %d bytes; the shard layout is required", size(map[string]any{"runs": runs, "reqs": reqs}))
}
