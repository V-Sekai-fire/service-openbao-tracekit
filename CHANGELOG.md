# Changelog

The frontier-learning record: what was tried, whether the level's pass rate rose, what was kept.

## Iteration 1: run methods

- Level: L4 RPC conformance (`register_run`, `decide`, `complete`, `close_run`).
- Tried: the engine run code (default-deny policy, identity from Bao's entity id, one `Put` per record, state rebuilt from the log).
  Written outside this session and adopted by the operator's decision.
- Found against upstream v1.4.2 (`d41c68e`): `close_run` replied `state: "closed"`, but the schema allows only `closing` or `open`.
  Upstream replies `closing` with the `run_seq` of the `run.final` it writes. Fixed.
- Kept: yes. New tests cover: no identity refused, default deny, `ask` and unknown answers never allow, run token bound to run and caller,
  retry returns the original reply, `request_id` conflict, reload from the log, and a failed write at each of the first six `Put`s leaves no gap.
- Not yet tested: the real v1.4.2 client against these methods, and the `.tkb` export.

## Iteration 2: harness and baseline

- Added `go run ./cmd/frontier`: one command with no arguments. It vets, builds both binaries, runs `go test -race -json` and prints s/n per level.
- Baseline (all 1.000): JCS 1/1, records 13/13, tree 5/5, checkpoints 16/16, proxy 11/11, engine 26/26.
- Gap: L2 authorisation, L3 identity (entity-alias login), the real v1.4.2 client against the run methods, and the `.tkb` export have no problems yet, so their rate is not measured.
- Next: add problems for L3 on a throwaway dev server before any engine change.

## Iteration 3: identity and scope through real Bao (L2, L3)

- Added `internal/e2e`: builds the plugin, starts `bao server -dev` on a free loopback port (never 8200) with a temp HOME and a minimal environment, and logs in over HTTP. Skips, and is reported as not measured, when `bao` is missing.
- Problems and results before the change (5 of 7 tests passing: 5 of the 6 subtests, and the parent failed with the one that failed): the entity id arrives with a userpass login; it survives token rotation; two principals get different entities and bob cannot use alice's run; root and plain tokens (no entity) are refused as `unauthenticated`; a scoped token with only `update` on `tracekit/rpc` and no default policy gets 403 on `sys/` and other paths. A single `update` capability is enough for `rpc`.
- Failed: a frame carrying `caller`, `principal` or `principal_token` was silently accepted.
- Change: `Serve` refuses those fields with `forbidden` before it opens the log. Unit test covers all four methods and checks no record is written.
- Result: L2-L3 e2e 7/7, engine 27/27, no other level dropped. Kept.
- Not tested: a production login method (userpass is test-only); `identity` as a frame field; records checked against the upstream event schema (`ValidateEvent`, `VerifyRecord`), which is the next regret item and the first thing that would break the `.tkb` export.
