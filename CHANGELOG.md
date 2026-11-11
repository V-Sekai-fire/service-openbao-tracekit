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

## Iteration 6: stored allow policy and approval_consume

- Level: L2 authorisation, L4 approval (`approval_consume`, allow and deny only), and the real v1.4.2 client with an allowed call.
- Tried: an operator-written allow list in Bao storage (`policy` path, read and write guarded by Bao's ACL). With none stored the default deny applies. A stored value must parse strictly as `{"allow": [non-empty strings]}`; anything else is `TK-POLICY-INVALID`, which denies. A write without `allow` is refused. A storage read error answers `unavailable` and writes nothing.
- Tried: `approval_consume` for a call the engine decided. It is read-only: an allow decision whose arguments match the decided ones returns `ok: true`; a denied, unknown, or argument-mismatched call is refused with `TK-APPROVAL-REQUIRED` or `TK-APPROVAL-MISMATCH`. It writes no record, so a replay gets the same answer.
- Found: the first real-client allow run failed on `args_digest` until the engine computed the client's digest (iteration 2, commit 0e28535). The allow path is now exercised end to end with the unmodified v1.4.2 client.
- Found and fixed by test: stored policies with trailing data, duplicate keys, extra keys, or a non-array `allow` were accepted; they now deny with `TK-POLICY-INVALID`.
- Kept: yes. Measured with `go run ./cmd/frontier` and the tools interpreter: L1-L5 45/45, L2-L3 real Bao 10/10, real-client allow passes. One earlier frontier run reported `TestRealClientAllow` failing (9/10); it did not reproduce in about 30 repeated runs. Cause not found.
- Not done: refusal records (`approval.refused`) are not written, so a refused consume leaves no trace in the signed log. `attempt` is not yet bound: local `decide` defaults it to 1 while upstream defaults to 0 and the client never sends it. Policy writes are not in the signed log and decisions carry no `policy_hash`. `approval_request`, `approval_decide`, and `ask` are not implemented.

## Iteration 7: frontier fails closed on missing measurement

- Problem: `go run ./cmd/frontier` could exit 0 when a level was not measured. A skipped test printed `NOT MEASURED` without changing the exit status. A package whose tests all skipped produced no table line. A failing `go test` run was ignored (`_ = cmd.Wait()`).
- Before: read from the code, not run. With the Tracekit environment unset, the frontier would have exited 0 with L2-L3 at 8/8.
- Change: each skipped test sets a failure and is listed by name. Every level needs a package that ran tests; otherwise it prints `NOT MEASURED: no tests ran` and fails. A level whose tests all skipped prints `NOT MEASURED: all N skipped` and fails. A non-zero `go test` exit fails the run.
- Result: `go vet ./...` clean. With `TRACEKIT_REF` and `TRACEKIT_PYTHON` set: all levels 100%, L2-L3 10/10, exit 0. With both unset: L2-L3 8/8, `NOT MEASURED` lists `TestRealClient` and `TestRealClientAllow`, exit 1. With `bao` off PATH and the Tracekit environment unset: L2-L3 0/0 `all 4 skipped`, exit 1.
- Not tested: a failing test through this path (the FAIL line was not exercised); a package that fails to compile (the non-zero `go test` exit path was not exercised).
- Renumbered: the duplicate `## Iteration 3` heading is now iteration 6 (stored allow policy); this gate is iteration 7.

## Iteration 8: bind attempt to the upstream default

- Problem: `decide` defaulted `attempt` to 1. Upstream defaults it to 0, and the client never sends it.
- Change: the default is 0 in `internal/engine/runs.go`. A sent `attempt` is still used as-is.
- Result: `go vet ./...` clean. Frontier with the Tracekit environment set: all levels 100%, L2-L3 10/10, exit 0.
- Not tested: a decision with `attempt` sent explicitly and a non-zero value through the real client.

## Iteration 9: approval.refused records

- Reverses iteration 6 for refusals: a refused `approval_consume` now writes one signed `approval.refused` record (`{tool_use_id, rule_ids, reason}`, source `signer`), committed through the request_id cache. A retry with the same request_id writes nothing and gets the original answer; a new request_id writes a second record. Allowed calls still write nothing.
- Correction: the iteration 6 claim "consume writes nothing" was never measured. `countKeys` lists top-level names, so `records/` counted as one entry and `TestConsumeWritesNothing` passed for any number of writes. It now counts `records/` entries (`countRecords`).
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     46/46  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
- Not tested: upstream schema and signature checks for `approval.refused` (not yet in `TestEveryRecordPassesUpstream`).
- Flaky check: `TestRealClientAllow` with `-race -count=50` passed (0 failures, 99 s). The single 9/10 from iteration 6 did not reproduce; parked.

## Iteration 10: run.closing before run.final

- Problem: `close_run` wrote only `run.final`. Upstream writes `run.closing` first, then `run.final`.
- Before: `TestCloseWritesClosingBeforeFinal` failed with `[signer.epoch run.registered run.final]`.
- Change: `closeRun` returns `[run.closing, run.final]`, written back to back. `run.closing.reason` is always `close_run`: the schema enum is `close_run | idle_timeout | quarantine`, and a free-text reason failed `TestEveryRecordPassesUpstream`. The reply still rides on `run.final`.
- Grace: upstream waits `grace_s` (5 s) for late records. Here the gap is 0. The upstream verifier and CLI wait for `run.final`, not a timer, so back-to-back is compatible. Late `complete` calls after close are still refused, as before.
- Not tested: a crash between the two writes. A retry then sees `run.closing` on the log but not `run.final`, and writes a second `run.closing`. Needs a guard on `runState`; not done here.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     47/47  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000

## Iteration 11: policy_hash on policy.decision

- Problem: `policy.decision` carried no `policy_hash`, so a decision could not be tied to the policy it was made under.
- Before: `TestDecisionCarriesPolicyHash` failed with `policy_hash ""`.
- Change: `policyFor` returns the hash with the policy: `sha256:` plus SHA-256 of the JCS of the stored allow list (of the raw bytes when the stored value does not parse). `decide` writes it into `policy.decision` data.
- Not covered: no stored policy hashes `{"allow":[]}`. The engine's own `Policy` function has no canonical form, so a test policy is not reflected in the hash. Approval records do not carry `policy_hash` yet. No `policies/<sha256>.json` snapshot is written; the v2 export in step (f) needs one.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     48/48  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000

## Iteration 12: strict zip writer for .tkb bundles (step f1)

- Step 0, read-only, from the code: `env -u PYTHONHOME PYTHONPATH=<ref> python -m tracekit verify tests/golden/v2/closed.tkb --trust tests/golden/v2/trust.json` exits 0 and prints `Integrity: VERIFIED.` That is the acceptance line.
- Policies: `verify/v2.py` checks a policy snapshot only for a decision an agent was asked to approve. A missing snapshot is an `unchecked` note, not a failure (around line 870). An empty `policies/` is therefore accepted for runs with no asked decision. No snapshot format was invented.
- Trust: `logs` and `algs` are required and non-empty. `witnesses` and `witnesses_required` are optional; the golden trust uses one witness.
- Zip metadata of the golden bundles: method 8 (deflate), flags 0, fixed DOS timestamp 2026-10-10 05:49:22, manifest not sorted by name. This writer uses method 0 (stored, allowed by section 9) with the same fixed timestamp. Name order is not mirrored and was not checked against the verifier.
- Change: `internal/bundle.Write` is a hand-rolled zip writer: stored entries, flags 0, no extra field, no comment, no zip64. It checks names (the section 9 pattern, no `.` or `..` segment), duplicates, the 10,000-entry, 64 MiB per entry and 512 MiB total limits. `archive/zip` was not used because its `Create` sets a data descriptor and a modified-time extra field.
- Frontier: `L5 export: .tkb (strict zip)` row added, so the package cannot go silently unmeasured.
- Not done: no bundle is built from the engine yet (f2), and no bundle has been run through upstream `verify` yet. This step proves the zip layout in Go only.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     48/48  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               4/4   1.000

## Iteration 13: refused consume is schema-checked

- Gap closed: the `approval.refused` record from iteration 9 was not validated against the upstream schema. `TestEveryRecordPassesUpstream` now runs a refused `approval_consume` on the denied call, so the record is checked with `ValidateEvent` and `VerifyRecord`. `run.closing` was already covered by that test through `close_run`.
- Before: not measured (the record was never in the checked set).
- Result: `TestEveryRecordPassesUpstream` passes. Frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     48/48  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               4/4   1.000

## Iteration 14: separate checkpoint log key

- Change: the init state gains `LogSeed`, a 32-byte Ed25519 seed separate from the record signer seed, generated with the other secrets and never exported. `LogPublicKey()` derives the public key for `trust.json`.
- Compatibility: an init state stored before this change has no `LogSeed` and now fails closed as malformed. It has to be re-initialised; there is no migration.
- Test: `TestLogKeyStableAndSeparate` checks the key is 32 bytes, differs from the record signer key, and is unchanged after a reload.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     49/49  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               4/4   1.000

## Iteration 15: bundle assembly without proofs (step f2a)

- Change: `internal/bundle.Assemble` builds `runs/<id>.jsonl` (id = first 32 hex of SHA-256 of `tenant/run_id`), `keys/records.jsonl` and `manifest.json` (format, verifier_min_version, files as bare sha256 hex). Lines are used verbatim and checked against the 256 B to 1 MiB bounds, and must not contain a newline.
- Not in this step: `proofs/records.json`, `checkpoints/<size>.note`, `trust.json`, and any upstream verify run. The output is not a verifiable bundle yet; the golden bundle's verifier acceptance is still open.
- Tests: manifest lists every file with the right hash; run lines are verbatim; short and newline-bearing lines are refused; run file names are shaped and distinct.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     49/49  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               7/7   1.000

## Iteration 16: inclusion proofs and a signed checkpoint note (step f2b)

- Change: `bundle.Note` builds a checkpoint note over (origin, size, root) and signs it with the log key (type 0x01). `bundle.Proofs` builds RFC 6962 inclusion proofs as base64 hashes for chosen indices.
- Tests: `TestProofsRebuildTheRoot` rebuilds each root from its leaf and proof (RFC 9162 walk). `TestNoteSignatureVerifies` checks the log signature over the note body with the log public key.
- Not in this step: `trust.json` generation, `proofs/records.json` assembly, and any upstream `verify` run. The bundle is still not verifiable.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     49/49  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 17: run.final head names run.closing; crash between them refuses writes

- Defect (found by test, before the fix): `run.final`'s `head_hash` was the hash of the record before `run.closing`, while `head_run_seq` named `run.closing`. `TestCloseHeadNamesRunClosing` failed with `head_hash sha256:2da4… is not the run.closing hash sha256:863b…`.
- Fix: `spec` carries `dataFn`, evaluated inside `commit` after the earlier records of the request are applied. `run.final` takes its head from the state then.
- Defect (reasoned from the code, covered by test): a crash after `run.closing` left the run accepting `decide` and `complete`, because only `run.final` set `closed`. `runState` gains `closing`, set in `apply` on `run.closing`. `decide`, `complete` and `consume` refuse while it is set. A retry after a crash writes only `run.final`.
- Tests: `TestCloseHeadNamesRunClosing`; `TestCloseCrashBetweenClosingAndFinal` fails the Put of `run.final` once, checks decide is refused while closing, then retries and checks exactly one `run.closing` and one `run.final` with the head fixed.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     51/51  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 18: export a closed run as a .tkb that upstream verify accepts (step f2c)

- Measured: `Engine.Export` builds the bundle files for one closed run: its records verbatim, the `signer.epoch` key records, inclusion proofs over the whole log for the run's first and last record and every key record, and a checkpoint signed by the log key, with origin `LogOrigin()`. `TestExportVerifiesUpstream` writes `trust.json` (the log vkey, `algs` ed25519, `witnesses_required` 0) to a temp dir and runs upstream `tracekit verify --trust` with PYTHONPATH set explicitly.
- Measured, clean: the export passes upstream verify. The test requires exit 0 and the line `Integrity: VERIFIED.`.
- Measured, tamper: one value in the run.registered record was changed, and that file's manifest hash was recomputed. Upstream rejects it with a non-zero exit and `[FAIL] signatures` naming `seq 1: hash does not match the event`. The run chain also fails at run_seq 1 onward.
- Inferred, not measured: the requirement from the plan was `[FAIL] chain intact`. This verifier does not use that name for this edit; the golden fixture used it for a different edit. The assertion now requires the signatures line and the seq, which identifies the same record.
- Not done: open runs (refused), run-sets, rekor/tsa anchors, policies, witnesses, and the bundle is not yet produced over HTTP (f3). Monitor and issuer checks are not configured in trust.json.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     52/52  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 19: a non-zero attempt is carried on the decision

- Measured: `decide` with `attempt: 2` writes a `policy.decision` whose `attempt` is 2. `TestNonZeroAttemptIsCarried`.
- Note: the first run of this test failed on a comparison in the test itself (the value was 2, my type assertion was wrong), not in the engine. The comparison now uses the printed value.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     53/53  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 20: export and trust read paths (step f3, part 1)

- Added: `runs/<tenant>/<run_id>/export` (read) returns `bundle.Write(Export(...))` as `application/zip` through `HTTPRawBody`. An open or unknown run returns 409 with an error frame. `trust` (read) returns only `logs`, `algs` and `witnesses_required`, with the log's public verification key.
- Measured in process: the export body is byte-equal to `bundle.Write(Export(...))`; an open run is refused with 409 and no zip; the trust response has exactly three keys and `logs[0]` equals `VKey(LogOrigin(), ed25519, LogPublicKey())`.
- Not measured: the ACL. The agent token must get 403 on both paths; that extension to the e2e test is the next step. Not measured through real Bao yet.
- Not measured: `TestExportVerifiesUpstream` is skipped unless the Tracekit environment is set; the frontier run had it set.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     56/56  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 21: agent token gets 403 on export and trust (ACL)

- Measured through real `bao server -dev`: the scoped agent token (policy: `update` on `tracekit/rpc` only) is refused on `GET tracekit/trust` and `GET tracekit/runs/default/x/export`. `TestIdentityAndScope/the_scoped_token_reaches_nothing_else` checks these with the existing 403-or-404 rule.
- Not done: a separate operator policy for export and trust. Export and trust are reachable only by a token granted those paths, and none is granted to the agent. The operator path itself is not yet exercised end to end; that is part of the end-to-end test.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     56/56  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 22: transactional test rig (transactions, step 1)

- Reading of "add transactions": the engine's writes go through Bao's interactive transactions (`logical.TransactionalStorage`), not single Puts. This step only makes the test storage transactional; no behaviour changes.
- Change: `newRig` now wraps the SDK's transactional inmem backend (`inmem.NewInmem`) in `logical.NewLogicalStorage`, which forwards `BeginTx`. `TestRigStorageIsTransactional` checks the type assertion and a begin/rollback round trip.
- Not in this step, on purpose: the fail-closed refusal in `ensure()` for non-transactional storage. Adding it now would refuse the `flaky` and `failOn` test doubles, which embed plain `logical.Storage`, and so break the crash and write-failure tests. It moves to step 2, where the doubles are re-wrapped to forward `BeginTx`.
- Parked: the red test `TestStorageHoldsOnlyNamedKeys` is kept out of the tree (scratch) so the gate stays green; it is re-added with the constant-storage steps.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     57/57  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 23: each commit runs in a transaction (transactions, step 2)

- Change: `commit()` writes its record inside `BeginTx` / `Put` / `Commit`, and applies the in-memory state only after the commit succeeds. `ensure()` refuses storage that is not `logical.TransactionalStorage`, with no fallback to plain Puts.
- Tests: the `flaky` and `failOn` doubles forward `BeginTx`; their failure counts and needles apply to the Put inside the transaction, so the existing no-gap, resume and crash tests cover the transactional path.
- Not done in this step: records still go to `records/` (the state split, the outbox and the removal of `records/` are steps 3 to 5); a dedicated Commit-failure test (a double whose Commit fails, asserting nothing changed); an explicit e2e assertion that the dev server reports transactional storage. The fork's `BeginTx` is still unreviewed.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     57/57  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 24: one transaction per request (step 3a)

- Change: `Serve` runs every record of a request, and so its state, in one storage transaction (`inTx`). A failed commit reloads state from storage on the next call. `ensure()` writes its epoch record through the same helper.
- Test change: `TestCloseCrashBetweenClosingAndFinal` became `TestCloseIsAllOrNothing`. A close whose `run.final` cannot be written now rolls back, so `run.closing` is not persisted and the run stays open. Previously it asserted the resume behaviour, which no longer exists.
- Evidence about the dev server (inferred from the gate, not asserted directly): the real-Bao e2e tests pass 10/10 with `ensure()` refusing non-transactional storage, so the storage a plugin gets from `bao server -dev` reports transactions.
- Not done: the state-key split (`state`, `runs/`, `reqs/`), the 300 s replay window and pruning, and dropping a run's state at `run.final`. Those are steps 3b and 3c. The fork's `BeginTx` (no commit retry, no handling of FDB's 5 s or 10 MB limits) is still unreviewed; step 3 depends on it.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     57/57  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 25: measured state layout (step 3b-i, sub-step a)

- Test: `TestStateWorstCaseFits` (internal/engine/state_layout_test.go) fills the caps: 64 runs x 8 calls, 512 ring entries, IDs at 128 bytes. The 128-byte cap is the one the user chose after the upstream schema limit (rpc_schema.py `ID` = 128) was shown; the 64-byte cap in the plan is superseded.
- Result: the largest 8-run or 64-entry shard is 30,017 bytes against a 92,160-byte budget (about 90 KiB, under FDB's ~100 KB value limit). A single value holding all runs and ring entries would be 471,315 bytes, so the layout must be sharded. Decision: fixed shard keys, read and written on every request.
- Limitation, stated plainly: the test encodes model structs, not the production state types. The production encoding is measured again in sub-step (b), when the state is written through the transaction; the budget check then applies to production bytes.
- Not changed: the engine's behaviour, storage keys and export. `constant_work_test.go` and `TestStorageHoldsOnlyNamedKeys` remain outside the tree until their steps.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     58/58  1.000
    L2-L3 e2e: identity and scope (real Bao)  10/10  1.000
    L5 export: .tkb (strict zip)               9/9   1.000

## Iteration 26: real client through a fake Hermes agent (e2e)

- Scope: `internal/e2e/fake_hermes_agent.py` drives the unmodified v1.4.2 client through the Hermes hook surface (`tracekit/integrations/hermes.py`, `hooks()`), with no LLM and no Hermes install. `TestFakeHermesAgent` runs it through the proxy against a dev Bao, with the scoped agent token.
- Behaviour checked: nine sequential allowed calls (above the in-flight cap of 8); a call off the allow list is blocked; an `approval_consume` for an undecided call is refused; a repeated `request_id` returns an identical reply; a reused `request_id` with another payload returns `conflict`; the run closes; the client warns about nothing.
- Replay detail: the first attempt sent two `decide` calls that were not byte-identical, because the client assigns a fresh `client_seq` per event call. The retry now uses its own run with a pinned stream and `client_seq`, which matches a connection-loss retry. This was a test bug, not an engine finding.
- Not covered, on purpose: export and `tracekit verify --trust` (this moves to the operator tool in step 4); tamper; concurrent agents. Dev-server storage is in-memory, so commit conflicts on FDB are not exercised.
- Result: frontier exit 0 with the Tracekit environment set:
    L0 format: JCS                             1/1   1.000
    L0 format: records                        13/13  1.000
    L0 format: tree                            5/5   1.000
    L0 format: checkpoints                    16/16  1.000
    L1 transport: proxy                       11/11  1.000
    L1-L5 engine: frames, runs, atomicity     58/58  1.000
    L2-L3 e2e: identity and scope (real Bao)  11/11  1.000
    L5 export: .tkb (strict zip)               9/9   1.000
