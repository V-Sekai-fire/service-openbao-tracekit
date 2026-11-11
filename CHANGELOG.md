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

## Iteration 4: every record passes the upstream event schema (L4)

- Problem: `TestEveryRecordPassesUpstream` runs register, allow, deny, ok and error completes and close, then checks each stored record with upstream `ValidateEvent` and `VerifyRecord` (Go verifier pinned at `ca403f5`).
- Before: 0 of 6 record types passed. `run.registered` used identity scheme `bao-entity` (not in the schema enum); `tool.call` carried decision fields and no `input`; `tool.result` had no `ok` or `output`; `run.final` had no `head_run_seq` or `head_hash`.
- Change: identity scheme is now `token` (subject is the Bao entity id). `decide` writes `tool.call` (arguments as a salted HMAC commitment, never the value) then `policy.decision`. `complete` writes `ok` and a committed or redacted `output`, and checks `args_digest` against the call. `run.final` names the head run_seq and hash and drops `reason`.
- Atomicity: only the last record of a method carries the request id and reply. A crash between `tool.call` and `policy.decision` is resumed by the retry, which writes only the decision (`TestDecideResumesAfterPartialWrite`).
- Result: engine 30/30, e2e 7/7, nothing below dropped. Kept.
- Not tested: the identity string against upstream's RPC `IDENTITY` pattern in a real client run; `run.closing` before `run.final`; `request_id`, `stream` and `client_seq` fields on records; the `.tkb` export; the real v1.4.2 client against decide and complete.

## Iteration 5: the real v1.4.2 client through the proxy and real Bao (L4)

- Problem: `TestRealClient` runs the unmodified v1.4.2 Python client from a checkout (no install) against the proxy and a dev Bao: `hello`, `register_run`, `decide`, `complete`, `close_run`. It needs a Python that imports `rfc8785` (`TRACEKIT_PYTHON`); it skips otherwise, and the harness now reports skips as "not measured".
- Before: `decide` worked, but `complete` failed with `conflict: args_digest does not match the decision`. The engine hashed the raw args string; the client binds to `sha256(JCS({"tool","args"}))` with args strictly parsed, whatever `args_source` is. Every allowed call would have failed to complete.
- Change: the engine computes the client's digest. Raw args that do not parse strictly are denied as `TK-ARGS-INVALID` and bound by the hash of their text.
- Result: engine 30/30, e2e 8/8, nothing below dropped. Kept.
- Not tested: an allow decision against the real client (the default policy denies everything), `ask` and `approval_consume`, which the Hermes hook calls; `run.closing`; the `.tkb` export.

## Iteration 3: stored allow policy and approval_consume

- Level: L2 authorisation, L4 approval (`approval_consume`, allow and deny only), and the real v1.4.2 client with an allowed call.
- Tried: an operator-written allow list in Bao storage (`policy` path, read and write guarded by Bao's ACL). With none stored the default deny applies. A stored value must parse strictly as `{"allow": [non-empty strings]}`; anything else is `TK-POLICY-INVALID`, which denies. A write without `allow` is refused. A storage read error answers `unavailable` and writes nothing.
- Tried: `approval_consume` for a call the engine decided. It is read-only: an allow decision whose arguments match the decided ones returns `ok: true`; a denied, unknown, or argument-mismatched call is refused with `TK-APPROVAL-REQUIRED` or `TK-APPROVAL-MISMATCH`. It writes no record, so a replay gets the same answer.
- Found: the first real-client allow run failed on `args_digest` until the engine computed the client's digest (iteration 2, commit 0e28535). The allow path is now exercised end to end with the unmodified v1.4.2 client.
- Found and fixed by test: stored policies with trailing data, duplicate keys, extra keys, or a non-array `allow` were accepted; they now deny with `TK-POLICY-INVALID`.
- Kept: yes. Measured with `go run ./cmd/frontier` and the tools interpreter: L1-L5 45/45, L2-L3 real Bao 10/10, real-client allow passes. One earlier frontier run reported `TestRealClientAllow` failing (9/10); it did not reproduce in about 30 repeated runs. Cause not found.
- Not done: refusal records (`approval.refused`) are not written, so a refused consume leaves no trace in the signed log. `attempt` is not yet bound: local `decide` defaults it to 1 while upstream defaults to 0 and the client never sends it. Policy writes are not in the signed log and decisions carry no `policy_hash`. `approval_request`, `approval_decide`, and `ask` are not implemented.

## Iteration 6: frontier fails closed on missing measurement

- Problem: `go run ./cmd/frontier` could exit 0 when a level was not measured. A skipped test printed `NOT MEASURED` without changing the exit status. A package whose tests all skipped produced no table line. A failing `go test` run was ignored (`_ = cmd.Wait()`).
- Before: read from the code, not run. With the Tracekit environment unset, the frontier would have exited 0 with L2-L3 at 8/8.
- Change: each skipped test sets a failure and is listed by name. Every level needs a package that ran tests; otherwise it prints `NOT MEASURED: no tests ran` and fails. A level whose tests all skipped prints `NOT MEASURED: all N skipped` and fails. A non-zero `go test` exit fails the run.
- Result: `go vet ./...` clean. With `TRACEKIT_REF` and `TRACEKIT_PYTHON` set: all levels 100%, L2-L3 10/10, exit 0. With both unset: L2-L3 8/8, `NOT MEASURED` lists `TestRealClient` and `TestRealClientAllow`, exit 1. With `bao` off PATH and the Tracekit environment unset: L2-L3 0/0 `all 4 skipped`, exit 1.
- Not tested: a failing test through this path (the FAIL line was not exercised); a package that fails to compile (the non-zero `go test` exit path was not exercised).
- Not done: the `## Iteration 3` heading appears twice. The second section covers the stored allow policy, `approval_consume` and the real-client allow. Not renumbered here.
