"""Fake Hermes agent for the e2e test. It has no LLM and no Hermes install.

It drives the unmodified upstream Tracekit v1.4.2 client through the Hermes hook surface
(tracekit/integrations/hermes.py, hooks()) the way Hermes's agent loop calls it: pre_tool_call
before each tool call, post_tool_call after. Then it uses the same client to check engine
behaviour the hooks do not reach: a refused approval_consume, and request_id replay and conflict.

Reads TRACEKIT_REF (a v1.4.2 checkout), SIGNER_URL and SIGNER_TOKEN_FILE from the environment.
Prints one JSON object on stdout. Nothing is installed and nothing is written.
"""
import json
import os
import sys
import warnings

sys.path.insert(0, os.environ["TRACEKIT_REF"])
os.environ["TRACEKIT_SIGNER"] = os.environ["SIGNER_URL"]
os.environ["TRACEKIT_SIGNER_TOKEN_FILE"] = os.environ["SIGNER_TOKEN_FILE"]  # the client sends it as a Bearer header

out = {"allowed": [], "blocked": [], "warnings": []}
try:
    from tracekit.integrations import hermes
    from tracekit.sdk.client import Client
    from tracekit.signer.rpc_schema import RPCError

    with open(os.environ["SIGNER_TOKEN_FILE"]) as f:
        token = f.read().strip()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        pre, post = hermes.hooks(token=lambda: token)
        session = "fake-session"
        # Nine sequential calls: more than the in-flight cap of 8, so the test guards the
        # in-flight-versus-lifetime choice made for step b1.
        for i in range(9):
            tcid = f"call-{i}"
            args = {"command": f"echo {i}"}
            if pre(tool_name="bash", args=dict(args), tool_call_id=tcid, session_id=session) is None:
                out["allowed"].append(tcid)
                post(args=dict(args), result="ok", tool_call_id=tcid, session_id=session, status="ok")
            else:
                out["blocked"].append(tcid)
        # Not on the allow list: the default policy denies it.
        denied = pre(tool_name="rm", args={"path": "/"}, tool_call_id="call-rm", session_id=session)
        out["denied_message"] = denied.get("message") if isinstance(denied, dict) else None

        client = Client(token=token)
        run = client.run("hermes-fake")
        out["run_id"] = run.run_id

        # A consume for a call that was never decided must be refused by the engine.
        c = run.approval_consume("never-decided", "bash", "{}")
        out["consume_ok"] = bool(c.get("ok")) if isinstance(c, dict) else None
        out["consume_reason"] = c.get("reason") if isinstance(c, dict) else None

        # Replay on a run of its own, so client_seq 0 is fresh. The second frame is the same
        # bytes as the first (a connection-loss retry), with the stream and client_seq pinned.
        rrun = client.run("hermes-replay")
        out["replay_run_id"] = rrun.run_id
        pinned = dict(stream="replay-stream", client_seq=0, request_id="replay-1")
        try:
            first = rrun.decide("replay-call", "bash", '{"command":"ls"}', **pinned)
            second = rrun.decide("replay-call", "bash", '{"command":"ls"}', **pinned)
            out["replay_identical"] = first == second
        except RPCError as e:
            out["replay_identical"] = False
            out["replay_error"] = e.code
        try:
            rrun.decide("replay-call", "bash", '{"command":"pwd"}', **pinned)
            out["conflict_code"] = None
        except RPCError as e:
            out["conflict_code"] = e.code
        rrun.close()
        run.close()
        out["closed"] = bool(run.closed)
        out["warnings"] = [str(w.message)[:300] for w in caught]
except Exception as e:  # reported to the test, never swallowed
    out["error"] = type(e).__name__ + ": " + str(e)[:400]
print(json.dumps(out))
