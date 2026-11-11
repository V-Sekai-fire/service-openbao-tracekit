# service-openbao-tracekit

An OpenBao secrets engine that implements the [Tracekit](https://github.com/Cygnux-Labs/Tracekit) signer in pure Go.
It fails closed: any engine error, timeout or denial means the call does not run.

Status: early. Pinned to Tracekit tag v1.4.2 (RPC 15 to 19). Not a drop-in replacement yet.

Done and measured (`go run ./cmd/frontier`, no arguments):

- Strict parse and RFC 8785 canonicalisation, reusing the upstream independent Go verifier, against the published vectors.
- Record signing, the RFC 6962 tree and C2SP checkpoints with cosignatures, byte for byte against the upstream vectors.
- The `rpc` path (one string field, raw reply), `hello`, `register_run`, `decide`, `complete` and `close_run`, with a default-deny policy.
- Identity from Bao's entity id, checked through a real dev server. Frames cannot name their own caller or principal.
- `tkbao-proxy`: maps the client's `POST /v2/rpc` onto the engine and returns no frame on any Bao failure.
- A stored allow list (operator-written, default deny) and `approval_consume` for allowed calls, checked by the real v1.4.2 client.

Not done: a complete policy (the stored allow list is not in the signed log and decisions carry no `policy_hash`), approval requests and refusal records, `attempt` binding, `.tkb` export, event-schema validation of every record, a production login method, and the cutover from the live signer. See `CHANGELOG.md` and `docs/shim.md`.

## Rules

- Every hash and signature message is computed from strictly parsed input, never from bytes Bao decoded or re-encoded.
- The engine never puts payloads in telemetry. OTel goes to AppSignal as digests and metrics only.
- Develop against a throwaway `bao server -dev` on another port, never a live vault.
- No tokens, secrets or vault paths in this tree.

License: MIT.
