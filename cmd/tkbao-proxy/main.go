// Command tkbao-proxy lets the Tracekit client talk to the engine through Bao.
//
//	tkbao-proxy -listen 127.0.0.1:18443 -bao https://127.0.0.1:8200 -mount tracekit
//
// TLS to Bao is verified with the system roots plus $BAO_CACERT when set. Plain
// http to Bao is accepted only on a loopback address. The listener is loopback only.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/V-Sekai-fire/service-openbao-tracekit/internal/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18443", "loopback address to serve POST /v2/rpc on")
	bao := flag.String("bao", "", "Bao address, e.g. https://127.0.0.1:8200")
	mount := flag.String("mount", "tracekit", "mount path of the engine")
	flag.Parse()
	if err := run(*listen, *bao, *mount); err != nil {
		fmt.Fprintln(os.Stderr, "tkbao-proxy:", err)
		os.Exit(1)
	}
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func run(listen, bao, mount string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || !isLoopback(host) {
		return fmt.Errorf("-listen must be a loopback host:port")
	}
	u, err := url.Parse(bao)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("-bao must be an http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return fmt.Errorf("plain http to Bao is allowed only on loopback")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: nil}
	if ca := os.Getenv("BAO_CACERT"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("BAO_CACERT holds no certificate")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	target := u.Scheme + "://" + u.Host + "/v1/" + mount + "/rpc"
	srv := &http.Server{
		Addr:              listen,
		Handler:           proxy.New(target, &http.Client{Transport: tr, Timeout: 60 * time.Second}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	return srv.ListenAndServe()
}
