package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"

	_ "net/http/pprof"
)

var (
	tmpDir = "/tmp/"
)

func main() {
	log.SetLevel(log.DEBUG)

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

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

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
		certsCache: map[string]*tls.Certificate{}},
	)

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
		MITMExceptions: []string{"example.com"},

		OnRequest:  onRequest,
		OnResponse: onResponse,
		OnConnect:  onConnect,
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

	if req.URL.Host == "example.net" {
		body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
		res := proxyutil.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		session.SetProp("blocked", true)
		return nil, res
	}

	if req.URL.Host == "testgomitmproxy" {
		body := strings.NewReader("<html><body><h1>Served by gomitmproxy</h1></body></html>")
		res := proxyutil.NewResponse(http.StatusOK, body, req)
		res.Header.Set("Content-Type", "text/html")
		return nil, res
	}

	if req.URL.Path != "" && req.Method != http.MethodConnect {
		_, name := path.Split(req.URL.Path)
		session.SetProp("saveName", name)
	}

	return nil, nil
}

func fixName(session *gomitmproxy.Session, name interface{}) string {
	fname := session.ID() + "-" + name.(string)
	log.Debug("onResponse: write file name: %s %s %s", fname, session.Request().RequestURI, session.Request().Method)
	return fname
}

func onResponse(session *gomitmproxy.Session) *http.Response {
	res := session.Response()
	req := session.Request()
	log.Printf("onResponse: %s", req.URL.String())

	name, ok := session.GetProp("saveName")
	if !ok {
		return nil
	}
	dumpFile, err := os.Create(fixName(session, name))
	if err != nil {
		return proxyutil.NewErrorResponse(req, err)
	}
	origBody := res.Body
	pr, pw := io.Pipe()
	res.Body = pr
	multi := io.MultiWriter(dumpFile, pw)
	go func() {
		if _, err = io.Copy(multi, origBody); err != nil {
			log.Printf("onResponse: copy multi fail: %s", err.Error())
		}
		origBody.Close()
		dumpFile.Close()
		pw.Close()
	}()

	return res
}

func onConnect(_ *gomitmproxy.Session, _ string, addr string) (conn net.Conn) {
	host, _, err := net.SplitHostPort(addr)

	if err == nil && host == "testgomitmproxy" {
		// Don't let it connecting there, we'll serve it by ourselves.
		return &proxyutil.NoopConn{}
	}

	return nil
}

// CustomCertsStorage is an example of a custom cert storage.
type CustomCertsStorage struct {
	// certsCache is a cache with the generated certificates.
	certsCache map[string]*tls.Certificate
}

// Get gets the certificate from the storage.
func (c *CustomCertsStorage) Get(key string) (cert *tls.Certificate, ok bool) {
	cert, ok = c.certsCache[key]

	return cert, ok
}

// Set saves the certificate to the storage.
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}
