// Package proxy maps Tracekit's HTTP transport onto the engine's rpc path.
//
// The client sends POST /v2/rpc with one JSON frame. Bao decodes request JSON
// before a plugin sees it, so the proxy wraps the frame text in {"frame": "<text>"}
// and forwards it to <bao>/v1/<mount>/rpc with the client's Authorization header.
// The proxy holds no signing key.
//
// Fail closed: anything other than a 200 from Bao carrying a JSON body becomes a
// 502 with an empty body, which the Tracekit client treats as an unavailable
// signer, so the hook blocks the call. The proxy never retries a write.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxLine is upstream's MAX_LINE.
const MaxLine = 1 << 20

// Path is the path the Tracekit client posts to.
const Path = "/v2/rpc"

// Proxy forwards frames to one Bao mount.
type Proxy struct {
	// Target is the full URL of the engine's rpc path, e.g. https://127.0.0.1:8200/v1/tracekit/rpc.
	Target string
	// Client must carry a timeout below Hermes's hook timeout and below Bao's 90 s cut.
	Client *http.Client
}

// New returns a proxy with a 60 s timeout.
func New(target string, client *http.Client) *Proxy {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	if c.Timeout == 0 || c.Timeout > 60*time.Second {
		c.Timeout = 60 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Proxy{Target: target, Client: &c}
}

func refuse(w http.ResponseWriter, status int) {
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path || r.Method != http.MethodPost {
		refuse(w, http.StatusNotFound)
		return
	}
	if r.ContentLength < 0 {
		refuse(w, http.StatusLengthRequired)
		return
	}
	if r.ContentLength > MaxLine {
		refuse(w, http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxLine+1))
	if err != nil || int64(len(body)) != r.ContentLength {
		refuse(w, http.StatusBadRequest)
		return
	}
	// json.Marshal would swap invalid UTF-8 for U+FFFD and change the frame's bytes.
	if !utf8.Valid(body) {
		refuse(w, http.StatusBadRequest)
		return
	}
	wrapped, err := json.Marshal(map[string]string{"frame": string(body)})
	if err != nil {
		refuse(w, http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.Target, bytes.NewReader(wrapped))
	if err != nil {
		refuse(w, http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if a := r.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		refuse(w, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, MaxLine+1))
	// Engine replies are 200, or 413 with an error frame; Bao errors use other shapes.
	// Pass only a 200 JSON body through; everything else is "no frame".
	if err != nil || len(out) > MaxLine || resp.StatusCode != http.StatusOK ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		refuse(w, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
