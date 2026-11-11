package engine

import "github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"

// consume answers approval_consume for a call the engine decided. Only an allow
// decision whose arguments match the decided ones lets the call run; that answer
// is read-only (nil spec, no record). A refusal returns an approval.refused spec,
// which Serve commits through the request_id cache, so a retry with the same
// request_id writes nothing new and gets the same answer.
func (e *Engine) consume(obj map[string]any, id *Identity) (*spec, []byte) {
	if err := need(obj, "run_id", "run_token", "tool_call_id", "tool", "args_source", "args"); err != nil {
		return nil, err.frame()
	}
	r, rerr := e.runFor(obj, id)
	if rerr != nil {
		return nil, rerr.frame()
	}
	if r.closed || r.closing {
		return nil, (&rpcErr{CodeInvalidRequest, "the run is closed"}).frame()
	}
	callID, ok1 := str(obj, "tool_call_id")
	tool, ok2 := str(obj, "tool")
	if !ok1 || !ok2 {
		return nil, errorFrame(CodeInvalidRequest, "bad tool_call_id or tool")
	}
	refuse := func(rule, reason string) (*spec, []byte) {
		ruleIDs := []any{rule}
		resp := map[string]any{"ok": false, "rule_ids": ruleIDs, "reason": reason}
		sp := &spec{
			run: r, typ: "approval.refused", source: "signer", toolCallID: callID,
			data: map[string]any{"tool_use_id": callID, "rule_ids": ruleIDs, "reason": reason},
			resp: func(int) map[string]any { return resp },
		}
		return sp, mustCanonical(resp)
	}
	c := r.calls[callID]
	if c == nil || c.decision != "allow" {
		return refuse("TK-APPROVAL-REQUIRED", "approval required but none was requested for this call")
	}
	var argv any
	if src, _ := obj["args_source"].(string); src == "raw" {
		a, ok := obj["args"].(string)
		if !ok {
			return nil, errorFrame(CodeInvalidRequest, "raw args must be a string")
		}
		v, err := jcs.Parse([]byte(a))
		if err != nil {
			return refuse("TK-ARGS-INVALID", "the arguments are not canonical JSON")
		}
		argv = v
	} else {
		argv = obj["args"]
	}
	cb, err := jcs.Canonical(map[string]any{"tool": tool, "args": argv})
	if err != nil {
		return nil, errorFrame(CodeInvalidRequest, err.Error())
	}
	if jcs.SHA256Hex(cb) != c.argsDigest {
		return refuse("TK-APPROVAL-MISMATCH", "the arguments differ from the approved ones")
	}
	if c.done {
		return refuse("TK-APPROVAL-REQUIRED", "the call already completed")
	}
	return nil, mustCanonical(map[string]any{"ok": true, "rule_ids": []any{}})
}
