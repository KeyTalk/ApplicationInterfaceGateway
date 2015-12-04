package forfarmers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"keytalk-proxy/backends"
	_ "log"
	"net"
	"net/http"
	"time"

	"github.com/op/go-logging"
	"github.com/spacemonkeygo/openssl"
)

var log = logging.MustGetLogger("forfarmers")

type Connect struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`

	cema *backends.CertificateManager
	cama *backends.CacheManager
}

func (cs *ConnectSession) RoundTrip(r *http.Request) (*http.Response, error) {
	return cs.RoundTripper.RoundTrip(r)

}

func (cs *ConnectSession) DialTLS(network, address string) (net.Conn, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	cert99, err := openssl.LoadCertificateFromPEM(cs.certstr)
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	ctx.UseCertificate(cert99)

	pk99, err := openssl.LoadPrivateKeyFromPEM(cs.keystr)
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	ctx.UsePrivateKey(pk99)

	ctx.SetSessionCacheMode(openssl.SessionCacheClient)

	ctx.SetSessionId([]byte{1})

	ctx.SetVerifyMode(openssl.VerifyNone)

	conn, err := openssl.Dial("tcp", cs.c.Backend, ctx, openssl.InsecureSkipHostVerification)
	if err != nil {
		log.Error("Error dialing: %s", err.Error())
		return nil, err
	}

	host, _, err := net.SplitHostPort(address)

	host = cs.c.Host(host)

	if err = conn.SetTlsExtHostName(host); err != nil {
		log.Error("Error set tls ext host: %s", err.Error())
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(time.Minute * 10))

	err = conn.Handshake()
	if err != nil {
		log.Error("Error handshake: %s", err.Error())
		return nil, err
	}
	return conn, err
}

type ConnectSession struct {
	http.RoundTripper
	email   string
	certstr []byte
	keystr  []byte
	c       *Connect
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

	if len(keystr) == 0 {
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

	// check certificate
	cs := &ConnectSession{
		email:   email,
		c:       h,
		certstr: certstr,
		keystr:  keystr,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

var _ = backends.Register2("client-certificate", func() backends.Backend {
	cema, err := backends.NewCertificateManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	cama, err := backends.NewCacheManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return &Connect{
		cema: cema,
		cama: cama,
	}
})
