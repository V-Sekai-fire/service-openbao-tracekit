# service-openbao-tracekit

An OpenBao secrets engine that implements the [Tracekit](https://github.com/Cygnux-Labs/Tracekit) signer in pure Go.
It fails closed: any engine error, timeout or denial means the call does not run.

Status: early. Milestone 1 is done: `internal/jcs` parses strictly and canonicalises with RFC 8785 by reusing the
upstream independent Go verifier, and passes the published `tests/vectors/jcs.jsonl` (227 canonical rows, 23 error rows).

## Rules

- Every hash and signature message is computed from strictly parsed input, never from bytes Bao decoded or re-encoded.
- The engine never puts payloads in telemetry. OTel goes to AppSignal as digests and metrics only.
- Develop against a throwaway `bao server -dev` on another port, never a live vault.
- No tokens, secrets or vault paths in this tree.

## Planned milestones

1. Strict parse and JCS (done).
2. Records: sign, hash chain, RFC 6962 tree, checked against `sig_v2.jsonl`.
3. C2SP checkpoints, checked against `c2sp_checkpoint.json`.
4. `.tkb` export, accepted by the Python, TypeScript and Go verifiers.
5. The signer RPC (v22) over the mount.

License: MIT.
