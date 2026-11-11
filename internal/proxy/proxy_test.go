package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBao records what it receives and answers as configured.
type fakeBao struct {
	status           int
	ctype            string
	reply            string
	gotBody, gotAuth string
	hits             int
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits++
	b, _ := io.ReadAll(r.Body)
	f.gotBody, f.gotAuth = string(b), r.Header.Get("Authorization")
	w.Header().Set("Content-Type", f.ctype)
	w.WriteHeader(f.status)
	_, _ = io.WriteString(w, f.reply)
}

func setup(f *fakeBao) (*httptest.Server, *httptest.Server) {
	bao := httptest.NewServer(f)
	px := httptest.NewServer(New(bao.URL+"/v1/tracekit/rpc", nil))
	return bao, px
}

func post(t *testing.T, url, body string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Post(url+Path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestWrapsFrameAndPassesReplyThrough(t *testing.T) {
	f := &fakeBao{status: 200, ctype: "application/json", reply: `{"proto":[15,19]}`}
	bao, px := setup(f)
	defer bao.Close()
	defer px.Close()
	req, _ := http.NewRequest("POST", px.URL+Path, strings.NewReader(`{"method":"hello","n":1.0}`))
	req.Header.Set("Authorization", "Bearer abc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != `{"proto":[15,19]}` {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if f.gotBody != `{"frame":"{\"method\":\"hello\",\"n\":1.0}"}` || f.gotAuth != "Bearer abc" {
		t.Fatalf("bao saw %q auth %q", f.gotBody, f.gotAuth)
	}
}

// Anything but a 200 JSON body from Bao is "no frame": 502 and an empty body.
func TestBaoFailuresFailClosed(t *testing.T) {
	cases := map[string]fakeBao{
		"403":        {status: 403, ctype: "application/json", reply: `{"errors":["permission denied"]}`},
		"503 sealed": {status: 503, ctype: "application/json", reply: `{"errors":["Vault is sealed"]}`},
		"500":        {status: 500, ctype: "application/json", reply: `{"errors":["x"]}`},
		"413 frame":  {status: 413, ctype: "application/json", reply: `{"error":{"code":"quota_exceeded"}}`},
		"html":       {status: 200, ctype: "text/html", reply: `<html>`},
		"redirect":   {status: 307, ctype: "application/json", reply: `{}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := c
			bao, px := setup(&f)
			defer bao.Close()
			defer px.Close()
			resp, body := post(t, px.URL, `{"method":"hello"}`)
			if resp.StatusCode != 502 || body != "" {
				t.Fatalf("%d %q", resp.StatusCode, body)
			}
		})
	}
}

func TestUnreachableBaoFailsClosed(t *testing.T) {
	bao := httptest.NewServer(&fakeBao{})
	target := bao.URL + "/v1/tracekit/rpc"
	bao.Close()
	px := httptest.NewServer(New(target, nil))
	defer px.Close()
	resp, body := post(t, px.URL, `{"method":"hello"}`)
	if resp.StatusCode != 502 || body != "" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

// Invalid UTF-8 is refused before Bao is asked, so it is never rewritten to U+FFFD.
func TestInvalidUTF8NeverReachesBao(t *testing.T) {
	f := &fakeBao{status: 200, ctype: "application/json", reply: `{}`}
	bao, px := setup(f)
	defer bao.Close()
	defer px.Close()
	resp, _ := post(t, px.URL, "{\"method\":\"hello\",\"s\":\"\xff\"}")
	if resp.StatusCode != 400 || f.hits != 0 {
		t.Fatalf("status %d hits %d", resp.StatusCode, f.hits)
	}
}

func TestSizeAndRouteLimits(t *testing.T) {
	f := &fakeBao{status: 200, ctype: "application/json", reply: `{}`}
	bao, px := setup(f)
	defer bao.Close()
	defer px.Close()
	if resp, _ := post(t, px.URL, strings.Repeat("a", MaxLine+1)); resp.StatusCode != 413 {
		t.Errorf("oversize: %d", resp.StatusCode)
	}
	if resp, err := http.Get(px.URL + Path); err != nil || resp.StatusCode != 404 {
		t.Errorf("GET: %v %v", resp, err)
	}
	resp, err := http.Post(px.URL+"/v1/rpc", "application/json", strings.NewReader(`{}`))
	if err != nil || resp.StatusCode != 404 {
		t.Errorf("other path: %v %v", resp, err)
	}
	if f.hits != 0 {
		t.Errorf("bao was asked %d times", f.hits)
	}
}
