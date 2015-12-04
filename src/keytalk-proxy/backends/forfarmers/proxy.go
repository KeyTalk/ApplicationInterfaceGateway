package forfarmers

import (
	"keytalk-proxy/backends"
	"net"
	"net/http"
	"time"

	"github.com/spacemonkeygo/openssl"
)

func (h *Proxy) Host(host string) string {
	log.Info("Mapping request %s", host)
	if v, ok := h.Mapping[host]; ok {
		log.Info("Mapping host %s to %s", host, v)
		return v
	}
	return host
}

func (h *Proxy) NewSession(email string) (http.RoundTripper, error) {
	cs := &ProxySession{
		c: h,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

var _ = backends.Register2("proxy", func() backends.Backend {
	return &Proxy{}
})

type Proxy struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`
}

func (cs *ProxySession) DialTLS(network, address string) (net.Conn, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

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

type ProxySession struct {
	http.RoundTripper
	c *Proxy
}
