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
