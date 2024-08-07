// oneproxy for proxy any
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
)

var (
	dumpRequestDir = "/tmp/oneproxy/"
	proxyCache     = make(map[string]bool)
	nextProxy, _   = url.Parse("socks5://127.0.0.1:1080")
)

func main() {
	// Read the MITM cert and key.
	tlsCert, err := tls.LoadX509KeyPair("oneproxy.crt", "oneproxy.key")
	if err != nil {
		log.Fatal(err)
	}

	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Generate certs valid for 7 days.
	mitmConfig.SetValidity(time.Hour * 24 * 7)
	// Set certs organization.
	mitmConfig.SetOrganization("gomitmproxy")

	// Prepare the proxy.
	addr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 8888,
	}

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: addr,

		APIHost: "gomitmproxy",

		MITMConfig:     mitmConfig,
		MITMExceptions: []string{"example.com", "gateway.icloud.com.cn"},

		OnRequest:  onRequest,
		OnResponse: onResponse,
		OnConnect:  onConnect,
		NextProxy:  proxyFunc,
	})

	err = proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Stop the proxy.
	proxy.Close()
}

func onRequest(session *gomitmproxy.Session) (*http.Request, *http.Response) {
	req := session.Request()

	log.Printf("onRequest: %s %s", req.Method, req.URL.String())

	if req.URL.Host == "oneproxy.io" {
		b, _ := json.Marshal(proxyCache)
		body := bytes.NewReader(b)
		res := proxyutil.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		session.SetProp("blocked", true)
		return nil, res
	}

	if req.URL.Path != "" && req.Method != http.MethodConnect {
		_, name := path.Split(req.URL.Path)
		session.SetProp("saveName", name)
	}

	return nil, nil
}

func fixName(session *gomitmproxy.Session, name interface{}) string {
	fname := dumpRequestDir + session.ID() + "-" + name.(string)
	log.Debug("onResponse: write file name: %s %s %s", fname, session.Request().RequestURI, session.Request().Method)
	return fname
}

func onResponse(session *gomitmproxy.Session) *http.Response {
	res := session.Response()
	req := session.Request()
	log.Printf("onResponse: %s", req.URL.String())
	if res.StatusCode == http.StatusBadGateway && nextProxy != nil {
		log.Info("proxy: request error, add next proxy cache: %s", req.Host)
		proxyCache[req.Host] = true
		return nil
	}

	name, ok := session.GetProp("saveName")
	if !ok {
		return nil
	}
	dumpFile, err := os.Create(fixName(session, name))
	if err != nil {
		return proxyutil.NewErrorResponse(req, err)
	}

	res.Body = TeeReader(res.Body, dumpFile)

	return res
}

func TeeReader(r io.ReadCloser, w io.WriteCloser) io.ReadCloser {
	return &teeReader{r, w}
}

type teeReader struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}

func (t *teeReader) Close() error {
	t.r.Close()
	t.w.Close()
	return nil
}

func onConnect(_ *gomitmproxy.Session, _ string, addr string) (conn net.Conn) {
	host, _, err := net.SplitHostPort(addr)

	if err == nil && host == "testgomitmproxy" {
		// Don't let it connecting there, we'll serve it by ourselves.
		return &proxyutil.NoopConn{}
	}

	return nil
}

func proxyFunc(req *http.Request) (*url.URL, error) {
	if proxyCache[req.Host] {
		log.Info("proxy on: [%s] [%s]", req.Host, nextProxy.String())
		return nextProxy, nil
	}
	return nil, nil
}
