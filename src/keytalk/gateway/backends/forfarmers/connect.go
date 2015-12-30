package forfarmers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"keytalk/gateway/backends"
	_ "log"
	"net"
	"net/http"
	"time"

	proxy "keytalk/gateway/proxy"

	logging "github.com/op/go-logging"
	"github.com/spacemonkeygo/openssl"
)

var log = logging.MustGetLogger("certificate-authenticator")

var _ = proxy.Register("client-certificate", func(server *proxy.Server) backends.Backend {
	return &Connect{
		cema: server.CertificateManager,
		cama: server.CacheManager,
	}
})

type Connect struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`

	cema *backends.CertificateManager
	cama *backends.CacheManager
}

func (h *Connect) Host(host string) string {
	if v, ok := h.Mapping[host]; ok {
		return v
	}
	return host
}

func (h *Connect) NewSession(email string) (http.RoundTripper, error) {
	certstr, _ := h.cama.GetBytes(fmt.Sprintf("%s:cert", email))
	keystr, _ := h.cama.GetBytes(fmt.Sprintf("%s:key", email))

	if len(certstr) == 0 || len(keystr) == 0 {
		derBytes, priv, err := h.cema.Generate(email)
		if err != nil {
			return nil, err
		}

		cert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		certstr = pem.EncodeToMemory(cert)
		if err := h.cama.Set(fmt.Sprintf("%s:cert", email), cert); err != nil {
			return nil, err
		}

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		keystr = pem.EncodeToMemory(key)
		if err := h.cama.Set(fmt.Sprintf("%s:key", email), key); err != nil {
			return nil, err
		}
	}

	cert, err := openssl.LoadCertificateFromPEM(certstr)
	if err != nil {
		return nil, fmt.Errorf("Error loading generated certificate: %s", err.Error())
	}

	pk, err := openssl.LoadPrivateKeyFromPEM(keystr)
	if err != nil {
		return nil, fmt.Errorf("Error loading generated key: %s", err.Error())
	}

	cs := &ConnectSession{
		c:    h,
		cert: cert,
		pk:   pk,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

type ConnectSession struct {
	http.RoundTripper
	pk   openssl.PrivateKey
	cert *openssl.Certificate
	c    *Connect
}

func (cs *ConnectSession) RoundTrip(r *http.Request) (*http.Response, error) {
	return cs.RoundTripper.RoundTrip(r)
}

func (cs *ConnectSession) newCtx() (*openssl.Ctx, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}

	ctx.UseCertificate(cs.cert)
	ctx.UsePrivateKey(cs.pk)
	ctx.SetSessionCacheMode(openssl.SessionCacheClient)
	ctx.SetSessionId([]byte{1})
	ctx.SetVerifyMode(openssl.VerifyNone)
	return ctx, nil
}

func (cs *ConnectSession) DialTLS(network, address string) (net.Conn, error) {
	ctx, err := cs.newCtx()
	if err != nil {
		return nil, fmt.Errorf("Error creating openssl ctx: %s", err.Error())
	}

	conn, err := openssl.Dial("tcp", cs.c.Backend, ctx, openssl.InsecureSkipHostVerification)
	if err != nil {
		return nil, fmt.Errorf("Error dialing: %s", err.Error())
	}

	host, _, err := net.SplitHostPort(address)

	host = cs.c.Host(host)

	if err = conn.SetTlsExtHostName(host); err != nil {
		return nil, fmt.Errorf("Error set tls ext host: %s", err.Error())
	}

	conn.SetDeadline(time.Now().Add(time.Minute * 10))

	err = conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("Error handshake: %s", err.Error())
	}
	return conn, err
}
