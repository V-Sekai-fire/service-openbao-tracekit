package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/jcs"
	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/record"
)

// More upstream error codes.
const (
	CodeUnauthenticated = "unauthenticated"
	CodeUnavailable     = "unavailable"
	CodeConflict        = "conflict"
	CodeRunToken        = "run_token_invalid"
)

var zeroHash = "sha256:" + strings.Repeat("0", 64)

// Identity is the caller, taken from Bao and never from a request field.
type Identity struct{ Scheme, Subject string }

// Policy decides one tool call. Only "allow" lets a call run; any other answer is a deny.
type Policy func(tool string) (decision string, ruleIDs []string)

// DenyAll is the default policy: nothing runs until a real rule set exists.
func DenyAll(string) (string, []string) { return "deny", []string{"TK-ENGINE-NOPOLICY"} }

// Engine holds the signer state. The log in storage is the only truth: every
// record is one Put under records/<seq>, and the head, the runs and the
// request_id index are rebuilt from the log, so a single Put is the commit point.
// One mutex serialises writes; this assumes one active writer (the leader).
type Engine struct {
	Policy Policy
	Now    func() time.Time
	Rand   io.Reader

	mu      sync.Mutex
	loaded  bool
	cfg     initState
	signer  *record.Signer
	nextSeq int
	head    string
	runs    map[string]*runState
	reqs    map[string]reqInfo
}

// NewEngine returns an engine that denies every call.
func NewEngine() *Engine {
	return &Engine{Policy: DenyAll, Now: time.Now, Rand: rand.Reader}
}

type initState struct {
	LogID  string `json:"log_id"`
	Seed   []byte `json:"seed"`
	Secret []byte `json:"token_secret"`
}

type entry struct {
	Seq        int    `json:"seq"`
	Hash       string `json:"hash"`
	Record     string `json:"record"`
	Tenant     string `json:"tenant"`
	RunID      string `json:"run_id"`
	RunSeq     int    `json:"run_seq"`
	Type       string `json:"type"`
	Subject    string `json:"subject,omitempty"`
	Agent      string `json:"agent,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	DecisionID string `json:"decision_id,omitempty"`
	Decision   string `json:"decision,omitempty"`
	ReqKey     string `json:"req_key,omitempty"`
	ArgsDigest string `json:"args_digest,omitempty"`
	Payload    string `json:"payload,omitempty"`
	Response   string `json:"response,omitempty"`
}

type runState struct {
	tenant, runID, subject, agent string
	runSeq                        int
	head                          string
	closed                        bool
	calls                         map[string]*callState
}

type callState struct {
	decisionID, decision, argsDigest string
	done                             bool
}

type reqInfo struct{ payload, response string }

type rpcErr struct{ code, msg string }

func (r *rpcErr) frame() []byte { return errorFrame(r.code, r.msg) }

func (e *Engine) hex32() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(e.Rand, b); err != nil {
		panic("engine: no randomness: " + err.Error()) // never sign with weak ids
	}
	return hex.EncodeToString(b)
}

func num(i int) json.Number { return json.Number(fmt.Sprint(i)) }

func str(o map[string]any, k string) (string, bool) {
	v, ok := o[k].(string)
	return v, ok && v != ""
}

func need(o map[string]any, ks ...string) *rpcErr {
	for _, k := range ks {
		if _, ok := o[k]; !ok {
			return &rpcErr{CodeInvalidRequest, "missing " + k}
		}
	}
	return nil
}

func (e *Engine) mac(tenant, runID, subject string) string {
	m := hmac.New(sha256.New, e.cfg.Secret)
	for _, p := range []string{tenant, runID, subject} {
		fmt.Fprintf(m, "%d:%s", len(p), p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

func (e *Engine) issue(tenant, runID, subject string) string {
	return hex.EncodeToString([]byte(tenant)) + "." + e.mac(tenant, runID, subject)
}

// runFor checks the run token and that the caller is the identity the run was registered under.
func (e *Engine) runFor(obj map[string]any, id *Identity) (*runState, *rpcErr) {
	bad := &rpcErr{CodeRunToken, "run token does not match this run and caller"}
	runID, ok1 := str(obj, "run_id")
	tok, ok2 := str(obj, "run_token")
	if !ok1 || !ok2 {
		return nil, bad
	}
	th, mac, found := strings.Cut(tok, ".")
	tb, err := hex.DecodeString(th)
	if !found || err != nil {
		return nil, bad
	}
	tenant := string(tb)
	r := e.runs[tenant+"\x00"+runID]
	if r == nil || r.subject != id.Subject || !hmac.Equal([]byte(mac), []byte(e.mac(tenant, runID, id.Subject))) {
		return nil, bad
	}
	return r, nil
}

// ensure loads or creates the signer state. Called with the mutex held.
func (e *Engine) ensure(ctx context.Context, s logical.Storage) error {
	if e.loaded {
		return nil
	}
	e.runs, e.reqs, e.nextSeq, e.head = map[string]*runState{}, map[string]reqInfo{}, 0, ""
	raw, err := s.Get(ctx, "init")
	if err != nil {
		return err
	}
	if raw == nil {
		seed, secret := make([]byte, 32), make([]byte, 32)
		if _, err := io.ReadFull(e.Rand, seed); err != nil {
			return err
		}
		if _, err := io.ReadFull(e.Rand, secret); err != nil {
			return err
		}
		cfg := initState{LogID: e.hex32(), Seed: seed, Secret: secret}
		b, _ := json.Marshal(cfg)
		if err := s.Put(ctx, &logical.StorageEntry{Key: "init", Value: b}); err != nil {
			return err
		}
		e.cfg = cfg
	} else if err := json.Unmarshal(raw.Value, &e.cfg); err != nil {
		return err
	}
	if len(e.cfg.Seed) != ed25519.SeedSize || len(e.cfg.Secret) != 32 || e.cfg.LogID == "" {
		return fmt.Errorf("init state is malformed")
	}
	if e.signer, err = record.NewSigner(ed25519.NewKeyFromSeed(e.cfg.Seed)); err != nil {
		return err
	}
	keys, err := s.List(ctx, "records/")
	if err != nil {
		return err
	}
	sort.Strings(keys)
	for i, k := range keys {
		if k != fmt.Sprintf("%020d", i) {
			return fmt.Errorf("log has a gap or a stray key at %q", k)
		}
		v, err := s.Get(ctx, "records/"+k)
		if err != nil || v == nil {
			return fmt.Errorf("record %s unreadable", k)
		}
		var en entry
		if err := json.Unmarshal(v.Value, &en); err != nil || en.Seq != i {
			return fmt.Errorf("record %s malformed", k)
		}
		e.apply(en)
	}
	if e.nextSeq == 0 {
		epoch := spec{run: &runState{tenant: "default", runID: "signer"}, typ: "signer.epoch", source: "signer",
			data: map[string]any{"keys": []any{map[string]any{
				"kid": e.signer.KID, "alg": record.Alg, "spki": base64.StdEncoding.EncodeToString(e.signer.SPKI)}}}}
		if _, err := e.commit(ctx, s, epoch); err != nil {
			return err
		}
	}
	e.loaded = true
	return nil
}

func (e *Engine) apply(en entry) {
	e.nextSeq, e.head = en.Seq+1, en.Hash
	rk := en.Tenant + "\x00" + en.RunID
	r := e.runs[rk]
	if r == nil {
		r = &runState{tenant: en.Tenant, runID: en.RunID, calls: map[string]*callState{}}
		e.runs[rk] = r
	}
	r.runSeq, r.head = en.RunSeq+1, en.Hash
	switch en.Type {
	case "run.registered":
		r.subject, r.agent = en.Subject, en.Agent
	case "run.final":
		r.closed = true
	case "tool.call":
		r.calls[en.ToolCallID] = &callState{argsDigest: en.ArgsDigest}
	case "policy.decision":
		if c := r.calls[en.ToolCallID]; c != nil {
			c.decisionID, c.decision = en.DecisionID, en.Decision
		}
	case "tool.result":
		if c := r.calls[en.ToolCallID]; c != nil {
			c.done = true
		}
	}
	if en.ReqKey != "" {
		e.reqs[en.ReqKey] = reqInfo{en.Payload, en.Response}
	}
}

type spec struct {
	argsDigest               string
	run                      *runState
	typ, source              string
	data, extra              map[string]any
	toolCallID, decisionID   string
	decision, subject, agent string
	reqKey, payload          string
	resp                     func(runSeq int) map[string]any
}

// commit signs one record and writes it with a single Put. State changes only
// after the Put returns, so a failed write changes nothing in memory.
func (e *Engine) commit(ctx context.Context, s logical.Storage, sp spec) ([]byte, error) {
	r := sp.run
	prev := e.head
	if e.nextSeq == 0 {
		prev = zeroHash
	}
	runPrev := r.head
	if runPrev == "" {
		runPrev = zeroHash
	}
	ev := map[string]any{
		"schema_version": "tracekit.event.v2", "id": e.hex32(), "seq": num(e.nextSeq), "prev_hash": prev,
		"ts":     e.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"run_id": r.runID, "agent_id": "main", "parent_id": nil, "source": sp.source, "type": sp.typ,
		"data": sp.data, "log_id": e.cfg.LogID, "tenant": r.tenant, "run_seq": num(r.runSeq), "run_prev_hash": runPrev,
	}
	for k, v := range sp.extra {
		ev[k] = v
	}
	rec, err := e.signer.Sign(ev)
	if err != nil {
		return nil, err
	}
	line, err := record.Line(rec)
	if err != nil {
		return nil, err
	}
	var resp []byte
	if sp.resp != nil {
		if resp, err = jcs.Canonical(sp.resp(r.runSeq)); err != nil {
			return nil, err
		}
	}
	en := entry{Seq: e.nextSeq, Hash: rec["hash"].(string), Record: string(line), Tenant: r.tenant, RunID: r.runID,
		RunSeq: r.runSeq, Type: sp.typ, Subject: sp.subject, Agent: sp.agent, ToolCallID: sp.toolCallID,
		DecisionID: sp.decisionID, Decision: sp.decision, ReqKey: sp.reqKey, ArgsDigest: sp.argsDigest, Payload: sp.payload, Response: string(resp)}
	b, err := json.Marshal(en)
	if err != nil {
		return nil, err
	}
	if err := s.Put(ctx, &logical.StorageEntry{Key: fmt.Sprintf("records/%020d", en.Seq), Value: b}); err != nil {
		return nil, err
	}
	e.apply(en)
	return resp, nil
}

// Serve answers one frame for an authenticated caller (nil: none).
func (e *Engine) Serve(ctx context.Context, s logical.Storage, id *Identity, frame string) (int, []byte) {
	status, obj, body := parseFrame(frame)
	if obj == nil {
		return status, body
	}
	method, _ := obj["method"].(string)
	switch method {
	case "register_run", "decide", "complete", "close_run":
	default:
		return http.StatusOK, stateless(obj)
	}
	if id == nil || id.Subject == "" {
		return http.StatusOK, errorFrame(CodeUnauthenticated, "the caller has no entity identity")
	}
	// Identity comes from Bao only. This engine has no gateways and no OIDC issuers,
	// so a frame that names a caller or a principal is refused, never ignored.
	for _, k := range []string{"caller", "principal", "principal_token"} {
		if _, has := obj[k]; has {
			return http.StatusOK, errorFrame(CodeForbidden, k+" is not accepted: identity comes from the transport")
		}
	}
	reqID, ok := str(obj, "request_id")
	if !ok {
		return http.StatusOK, errorFrame(CodeInvalidRequest, "missing request_id")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensure(ctx, s); err != nil {
		e.loaded = false
		return http.StatusOK, errorFrame(CodeUnavailable, "the signer log cannot be read or written")
	}
	canon, err := jcs.Canonical(obj)
	if err != nil {
		return http.StatusOK, errorFrame(CodeInvalidRequest, err.Error())
	}
	payload := jcs.SHA256Hex(canon)
	key := id.Subject + "\x00" + reqID
	if ri, seen := e.reqs[key]; seen {
		if ri.payload != payload {
			return http.StatusOK, errorFrame(CodeConflict, "request_id was used for another request")
		}
		return http.StatusOK, []byte(ri.response)
	}
	var sps []spec
	var rerr *rpcErr
	switch method {
	case "register_run":
		var sp spec
		sp, rerr = e.register(obj, id)
		sps = []spec{sp}
	case "decide":
		pol, perr := e.policyFor(ctx, s)
		if perr != nil {
			return http.StatusOK, errorFrame(CodeUnavailable, "the signer policy cannot be read")
		}
		sps, rerr = e.decide(obj, id, pol)
	case "complete":
		var sp spec
		sp, rerr = e.complete(obj, id)
		sps = []spec{sp}
	case "close_run":
		var sp spec
		sp, rerr = e.closeRun(obj, id)
		sps = []spec{sp}
	}
	if rerr != nil {
		return http.StatusOK, rerr.frame()
	}
	var resp []byte
	for i := range sps {
		sps[i].subject = id.Subject
		if i == len(sps)-1 {
			// Only the last record carries the request id and the reply, so a crash between
			// records is resumed by the retry and never replayed as an answer.
			sps[i].reqKey, sps[i].payload = key, payload
		}
		var err error
		if resp, err = e.commit(ctx, s, sps[i]); err != nil {
			e.loaded = false // the Put may have landed: reload from the log before the next call
			return http.StatusOK, errorFrame(CodeUnavailable, "the signer log cannot be read or written")
		}
	}
	return http.StatusOK, resp
}

func (e *Engine) register(obj map[string]any, id *Identity) (spec, *rpcErr) {
	var name string
	switch a := obj["agent"].(type) {
	case string:
		name = a
	case map[string]any:
		name, _ = a["name"].(string)
	}
	if name == "" {
		return spec{}, &rpcErr{CodeInvalidRequest, "missing agent"}
	}
	tenant, ok := str(obj, "tenant")
	if !ok {
		tenant = "default"
	}
	runID, ok := str(obj, "run_id")
	if !ok {
		runID = "run-" + e.hex32()
	}
	if _, exists := e.runs[tenant+"\x00"+runID]; exists {
		return spec{}, &rpcErr{CodeConflict, "run_id already registered"}
	}
	return spec{
		run: &runState{tenant: tenant, runID: runID}, typ: "run.registered", source: "signer", agent: name,
		data: map[string]any{
			"agent":    map[string]any{"name": name},
			"identity": map[string]any{"scheme": id.Scheme, "subject": id.Subject, "attested": true},
		},
		extra: map[string]any{"tenant_attested": false},
		resp: func(int) map[string]any {
			return map[string]any{"run_id": runID, "run_token": e.issue(tenant, runID, id.Subject), "tenant": tenant,
				"tenant_attested": false, "principal_attested": false}
		},
	}, nil
}

// commitment is the HMAC of a digest under a per-record salt derived from the log secret.
func (e *Engine) commitment(label, saltID, digest string) string {
	k := hmac.New(sha256.New, e.cfg.Secret)
	fmt.Fprintf(k, "salt:%s:%s", label, saltID)
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte(digest))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

func (e *Engine) decide(obj map[string]any, id *Identity, pol Policy) ([]spec, *rpcErr) {
	if err := need(obj, "run_id", "run_token", "stream", "client_seq", "tool_call_id", "tool", "args_source", "args"); err != nil {
		return nil, err
	}
	r, rerr := e.runFor(obj, id)
	if rerr != nil {
		return nil, rerr
	}
	if r.closed {
		return nil, &rpcErr{CodeInvalidRequest, "the run is closed"}
	}
	callID, ok1 := str(obj, "tool_call_id")
	tool, ok2 := str(obj, "tool")
	src, _ := obj["args_source"].(string)
	if !ok1 || !ok2 || (src != "raw" && src != "parsed" && src != "coerced") {
		return nil, &rpcErr{CodeInvalidRequest, "bad tool_call_id, tool or args_source"}
	}
	// The client binds complete to sha256(JCS({"tool", "args"})) with args strictly parsed,
	// whatever args_source says, so the engine computes the same digest. Raw args that do
	// not parse strictly are denied (TK-ARGS-INVALID) and bound by the hash of their text.
	var digest string
	var size int
	badArgs := false
	var argv any
	if src == "raw" {
		a, ok := obj["args"].(string)
		if !ok {
			return nil, &rpcErr{CodeInvalidRequest, "raw args must be a string"}
		}
		size = len(a)
		if v, err := jcs.Parse([]byte(a)); err != nil {
			badArgs, digest = true, jcs.SHA256Hex([]byte(a))
		} else {
			argv = v
		}
	} else {
		argv = obj["args"]
	}
	if !badArgs {
		cb, err := jcs.Canonical(map[string]any{"tool": tool, "args": argv})
		if err != nil {
			return nil, &rpcErr{CodeInvalidRequest, err.Error()}
		}
		digest = jcs.SHA256Hex(cb)
		if src != "raw" {
			size = len(cb)
		}
	}
	// A tool.call without its policy.decision is a crash between the two records:
	// the retry writes only the decision.
	pending := r.calls[callID]
	if pending != nil && pending.decisionID != "" {
		return nil, &rpcErr{CodeConflict, "tool_call_id already decided"}
	}
	if pending != nil && pending.argsDigest != digest {
		return nil, &rpcErr{CodeConflict, "tool_call_id was started with other arguments"}
	}
	decision, rules := pol(tool)
	if badArgs {
		decision, rules = "deny", []string{"TK-ARGS-INVALID"}
	}
	if decision != "allow" {
		decision = "deny" // fail closed: ask and anything unknown are not an allow
		if len(rules) == 0 {
			rules = []string{"TK-ENGINE-NOPOLICY"}
		}
	}
	ruleIDs := make([]any, len(rules))
	for i, x := range rules {
		ruleIDs[i] = x
	}
	did := "dec-" + e.hex32()
	attempt := json.Number("1")
	if a, ok := obj["attempt"].(json.Number); ok {
		attempt = a
	}
	extra := map[string]any{"args_source": src, "attempt": attempt, "tool_call_id": callID, "tenant_attested": false}
	decisionSpec := spec{
		run: r, typ: "policy.decision", source: "sdk", toolCallID: callID, decisionID: did, decision: decision, argsDigest: digest,
		data:  map[string]any{"tool_use_id": callID, "decision": decision, "rule_ids": ruleIDs, "tool": tool, "decision_id": did},
		extra: extra,
		resp: func(runSeq int) map[string]any {
			return map[string]any{"decision": decision, "decision_id": did, "rule_ids": ruleIDs, "run_seq": num(runSeq)}
		},
	}
	if pending != nil {
		return []spec{decisionSpec}, nil
	}
	saltID := e.hex32()
	callSpec := spec{
		run: r, typ: "tool.call", source: "sdk", toolCallID: callID, argsDigest: digest,
		data: map[string]any{"tool_use_id": callID, "name": tool, "salt_id": saltID,
			"input": map[string]any{"args": map[string]any{
				"hash": e.commitment("tool.call", saltID, digest), "size": num(size), "redacted": true}}},
		extra: extra,
	}
	return []spec{callSpec, decisionSpec}, nil
}

func (e *Engine) complete(obj map[string]any, id *Identity) (spec, *rpcErr) {
	if err := need(obj, "run_id", "run_token", "stream", "client_seq", "tool_call_id", "decision_id", "args_digest", "status"); err != nil {
		return spec{}, err
	}
	r, rerr := e.runFor(obj, id)
	if rerr != nil {
		return spec{}, rerr
	}
	if r.closed {
		return spec{}, &rpcErr{CodeInvalidRequest, "the run is closed"}
	}
	callID, _ := str(obj, "tool_call_id")
	did, _ := str(obj, "decision_id")
	status, _ := obj["status"].(string)
	digest, _ := str(obj, "args_digest")
	c := r.calls[callID]
	if c == nil || c.decisionID == "" || c.decisionID != did {
		return spec{}, &rpcErr{CodeConflict, "no such decision for this tool_call_id"}
	}
	if c.done {
		return spec{}, &rpcErr{CodeConflict, "tool_call_id already completed"}
	}
	if c.argsDigest != digest {
		return spec{}, &rpcErr{CodeConflict, "args_digest does not match the decision"}
	}
	if status != "ok" && status != "error" {
		return spec{}, &rpcErr{CodeInvalidRequest, "bad status"}
	}
	if c.decision != "allow" && status == "ok" {
		return spec{}, &rpcErr{CodeForbidden, "a denied call cannot complete as ok"}
	}
	data := map[string]any{"tool_use_id": callID, "ok": status == "ok", "decision_id": did}
	if res, has := obj["result"]; has {
		cb, err := jcs.Canonical(res)
		if err != nil {
			return spec{}, &rpcErr{CodeInvalidRequest, err.Error()}
		}
		saltID := e.hex32()
		data["salt_id"] = saltID
		data["output"] = map[string]any{
			"hash": e.commitment("tool.result", saltID, jcs.SHA256Hex(cb)), "size": num(len(cb)), "redacted": true}
	} else {
		data["output"] = map[string]any{"value": nil, "redacted": true}
	}
	return spec{
		run: r, typ: "tool.result", source: "sdk", toolCallID: callID, decisionID: did,
		data:  data,
		extra: map[string]any{"tool_call_id": callID, "tenant_attested": false},
		resp:  func(runSeq int) map[string]any { return map[string]any{"run_seq": num(runSeq)} },
	}, nil
}

func (e *Engine) closeRun(obj map[string]any, id *Identity) (spec, *rpcErr) {
	if err := need(obj, "run_id", "run_token"); err != nil {
		return spec{}, err
	}
	r, rerr := e.runFor(obj, id)
	if rerr != nil {
		return spec{}, rerr
	}
	if r.closed {
		return spec{}, &rpcErr{CodeConflict, "the run is already closed"}
	}
	// run.final has no reason field in the v2 schema; the head it names is the last record of the run.
	return spec{
		run: r, typ: "run.final", source: "signer",
		data:  map[string]any{"head_run_seq": num(r.runSeq - 1), "head_hash": r.head},
		extra: map[string]any{"tenant_attested": false},
		resp: func(runSeq int) map[string]any {
			return map[string]any{"run_id": r.runID, "state": "closing", "run_seq": num(runSeq)}
		},
	}, nil
}
