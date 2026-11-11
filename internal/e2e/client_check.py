"""Drives the real Tracekit v1.4.2 Python client through the proxy and prints one JSON object.

Run by internal/e2e/client_test.go only. Reads TRACEKIT_REF (a v1.4.2 checkout), SIGNER_URL and
SIGNER_TOKEN_FILE from the environment. Nothing is installed and nothing is written.
"""
import json
import os
import sys
import warnings

sys.path.insert(0, os.environ["TRACEKIT_REF"])

out = {}
try:
    from tracekit.format.canon import event_hash, loads_strict
    from tracekit.sdk.client import Client

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        client = Client(signer=os.environ["SIGNER_URL"], token_file=os.environ["SIGNER_TOKEN_FILE"])
        run = client.run("e2e")
        out["run_id"] = run.run_id
        args = '{"command":"ls"}'
        d = run.decide("c1", "bash", args)
        out["decision"] = d.get("decision")
        out["unavailable"] = d.get("unavailable", False)
        digest = event_hash({"tool": "bash", "args": loads_strict(args)})
        if os.environ.get("CHECK_MODE") == "allow":
            out["consume"] = run.approval_consume("c1", "bash", args)
            out["complete"] = run.complete("c1", status="ok", decision_id=d.get("decision_id"), args_digest=digest)
        else:
            out["complete"] = run.complete("c1", status="error", decision_id=d.get("decision_id"), args_digest=digest)
        run.close()
        out["closed"] = run.closed
        out["warnings"] = [str(w.message)[:300] for w in caught]
except Exception as e:  # reported to the test, never swallowed
    out["error"] = type(e).__name__ + ": " + str(e)[:400]
print(json.dumps(out))
