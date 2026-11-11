package engine

// LogOrigin is the checkpoint origin and the name of the log key. A verifier pins the key
// by this name in trust.json (`logs`); the note's origin line must match it.
func (e *Engine) LogOrigin() string { return "tracekit.local/log/" + e.cfg.LogID }
