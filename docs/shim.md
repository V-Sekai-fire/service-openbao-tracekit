# Client shim: Tracekit RPC over an OpenBao mount

Status: design. Facts below were read from Tracekit tag v1.4.2 (`d41c68e`) and measured on a throwaway
`bao server -dev` (bao 2.7.2, SDK 2.7.1). Items marked "unverified" were not tested.

## What the Hermes plugin sends

- The plugin calls `tracekit.sdk.client.Client`. For an `https://` or loopback `http://` signer it sends
  `POST /v2/rpc` with one JSON frame and reads one JSON frame back.
- Auth is `Authorization: Bearer <token>`, re-read from `$TRACEKIT_SIGNER_TOKEN_FILE` on every call.
- The first call is `hello`. The client checks the signer's protocol range (v1.4.2 speaks RPC 19; `main` speaks 22).
- Plain `http://` is allowed only on a loopback address. TLS trust comes from `$TRACEKIT_SIGNER_CA`.
- RPC refusals come back as HTTP 200 with an error frame. A transport failure makes the hook block the call.
- A second client, `tracekit/client.py`, posts to `/v1/rpc`. The Hermes plugin does not use it (unverified for
  other integrations).

## What Bao does to that

| Need | Bao behaviour (measured) |
|---|---|
| Path `/v2/rpc` | Bao serves only `/v1/<mount>/<path>`. No match. |
| Frame bytes | The request JSON is decoded to a map: numbers become float64, the last duplicate key wins, a lone surrogate becomes U+FFFD. |
| Exact bytes | A string field arrives exactly. `HTTPRawBody` replies leave byte-exact. |
| Bearer token | Bao accepts `Authorization: Bearer <token>` (measured in the second spike; `X-Vault-Token` also works). |

## Second spike (bao 2.7.2 dev, probe plugin, measured)

| Question | Result |
|---|---|
| Bearer header | `Authorization: Bearer <token>` is accepted; a wrong token gets 403. |
| Caller identity | `req.ClientTokenAccessor` and `req.DisplayName` (e.g. `token-hermes-agent`) arrive. `req.EntityID` is empty for a plain token, so identity must come from the token accessor or display name, or from an entity alias. |
| Scoped token | A token with a policy on `probe/who` and `probe/frame` only gets 403 on `sys/mounts` and on an ungranted `probe/slow`. The policy needs `create` as well as `update`, because the probe's existence check returned false, which turns writes into creates. The real `rpc` path may omit the check and need only `update` (untested). |
| Frame size | A 1 MiB and a 2 MiB string field both arrive intact (200). Upstream `MAX_LINE` is 1 MiB, so Bao's cap does not bind first. |
| Long request | A 100 s request failed at 90.002 s with HTTP 500 (`rpc error: code = Canceled desc = context canceled`). Bao cut it at its 90 s request limit on this dev server. The live build may be configured differently (untested). |

## Design

1. The engine mounts at `tracekit/` and has one write path, `rpc`, taking one field `frame` (a string).
2. The engine runs `internal/jcs.Parse` on `frame`, so duplicate keys, non-finite numbers, lone surrogates, unsafe
   integers and deep nesting are refused as `invalid_request`, as upstream does.
3. The engine replies through `HTTPRawBody` with `application/json`, so the client reads exactly what the engine wrote.
4. A small loopback proxy, `tkbao-proxy`, sits between the plugin and Bao. It maps `POST /v2/rpc` with body `B` to
   `POST /v1/tracekit/rpc` with body `{"frame": <B as a JSON string>}`, forwards the bearer token, and returns Bao's
   raw reply unchanged. It holds no signing key.
5. No Tracekit fork is needed if the proxy works. A V-Sekai-fire fork of the client is the fallback.

## Fail-closed rules

- The proxy answers any Bao error, timeout, 403, 503, seal, or malformed reply with a non-200 status and no frame.
  The client then raises `SignerUnavailable` and the hook blocks the call.
- The proxy never retries a write and never caches a decision.
- The engine never signs a record after a failed policy decision, and an unknown RPC method is refused.
- The proxy has a hard timeout shorter than Hermes's `plugins.hook_callback_timeout`.

## Identity

Tracekit takes the caller's identity from the transport, never from a request field. The engine will derive it from
the Bao token's entity and policies (`logical.Request.EntityID` is empty for a plain token, measured; an auth-method login that yields an entity alias is untested and is the likely route, since a display name is chosen by whoever mints the token and an accessor changes on rotation). Run tokens stay
as Tracekit defines them.

## Not decided

- Whether the proxy ships in this repo (Go, single binary) or as a launchd service in another repo.
- `approval_wait`: a held request cannot outlive Bao's 90 s limit on the dev server, so it needs a long-poll in chunks under that bound, or a raised limit on the live listener.
- Whether `tracekit-ai` installs on Hermes's Python 3.14.9. Its metadata says `requires-python >=3.9`.
- What the proxy trusts: it sits in the agent's trust zone, so it must hold only the agent's scoped token.
