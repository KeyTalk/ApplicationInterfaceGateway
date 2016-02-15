package forfarmers

import (
	"keytalk/gateway/backends"
	_ "log"
	"net"
	"net/http"
	"time"

	proxy "keytalk/gateway/proxy"

	"github.com/nmcclain/ldap"
	logging "github.com/op/go-logging"
	"github.com/spacemonkeygo/openssl"
)

var log = logging.MustGetLogger("ldap")

var _ = proxy.Register("ldap", func(server *proxy.Server) backends.Backend {
	c := &LdapBackend{}

	s := ldap.NewServer()
	s.EnforceLDAP = true

	s.BindFunc("", c)
	s.SearchFunc("", c)
	s.CloseFunc("", c)

	// if err := s.ListenAndServe("localhost:389"); err != nil {

	log.Debug("LDAP server started...")

	go s.ListenAndServe("127.0.0.1:8389")
	return c
})

type LdapBackend struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`
	ldap    *ldap.Conn
}

func (cs *LdapBackendSession) RoundTrip(r *http.Request) (*http.Response, error) {
	return cs.RoundTripper.RoundTrip(r)

}

func (cs *LdapBackendSession) DialTLS(network, address string) (net.Conn, error) {
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

type LdapBackendSession struct {
	http.RoundTripper
	email   string
	certstr []byte
	keystr  []byte
	c       *LdapBackend
}

func (h *LdapBackend) Host(host string) string {
	if v, ok := h.Mapping[host]; ok {
		return v
	}
	return host
}

func (h *LdapBackend) NewSession(email string) (http.RoundTripper, error) {
	// check certificate
	cs := &LdapBackendSession{
		email: email,
		c:     h,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

func (b *LdapBackend) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	log.Debug("Bind %s %s", bindDN, bindSimplePw)
	/*
		//l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", h.ldapServer, h.ldapPort))
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "ldap.forumsys.com", 389))
		if err != nil {
			return ldap.LDAPResultOperationsError, err
		}

		if err := l.Bind(bindDN, bindSimplePw); err != nil {
			return ldap.LDAPResultOperationsError, err
		}

		b.ldap = l

	*/
	//return ldap.LDAPResultInvalidCredentials, nil
	return ldap.LDAPResultSuccess, nil
}

func (b *LdapBackend) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	log.Debug("Search %s %#v", boundDN, searchReq)
	/*
		// 	return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
		search := ldap.NewSearchRequest(
			searchReq.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			searchReq.Filter,
			searchReq.Attributes,
			nil)
		sr, err := b.ldap.Search(search)
		if err != nil {
			return ldap.ServerSearchResult{}, err
		}

		log.Debug("P: Search OK: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
		log.Debug("%#v", ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess})
		pretty.Print(ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess})
	*/

	return ldap.ServerSearchResult{
		Entries: []*ldap.Entry{
			&ldap.Entry{
				DN: "uid=blabla,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					&ldap.EntryAttribute{
						Name:   "uid",
						Values: []string{"blabla"},
					},
				},
			},
		},
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
	// return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (b *LdapBackend) Close(boundDn string, conn net.Conn) error {
	return nil
}
