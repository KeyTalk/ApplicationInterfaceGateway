package forfarmers

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"keytalk/gateway/backends"
	_ "log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	proxy "keytalk/gateway/proxy"

	"github.com/kr/pretty"
	"github.com/nmcclain/ldap"
	logging "github.com/op/go-logging"
	"github.com/spacemonkeygo/openssl"
)

var log = logging.MustGetLogger("ldap")

var _ = proxy.Register("ldap", func(server *proxy.Server) backends.Backend {
	c := &LdapBackend{
		cema:     server.CertificateManager,
		cama:     server.CacheManager,
		sessions: map[string]*LdapBackendSession{},
	}

	s := ldap.NewServer()
	s.EnforceLDAP = true

	s.BindFunc("", c)
	s.SearchFunc("", c)
	s.CloseFunc("", c)

	log.Debug("LDAP server started...")

	// todo config
	// 192.168.102.152
	go s.ListenAndServe("0.0.0.0:389")
	return c
})

const authUrl = "https://127.0.0.1:8081/module/webmail.fe"

type LdapBackend struct {
	Backend  string            `toml:"backend"`
	Hosts    []string          `toml:"hosts"`
	Mapping  map[string]string `toml:"mapping"`
	ldap     *ldap.Conn
	sessions map[string]*LdapBackendSession
	cema     *backends.CertificateManager
	cama     *backends.CacheManager
}

func (cs *LdapBackendSession) Authenticate(email string) (*http.Response, error) {
	if cs.cookieJar != nil {
		return nil, nil
	}

	v := url.Values{}
	v.Set("name", email)
	//v.Set("password", cs.h.Password(email))
	v.Set("password", "Bej1a3OM")
	v.Set("CutomizeLogin", "Sign In")
	v.Set("reqAction", "1")
	v.Set("reqObject", "WMLogin")

	req, err := http.NewRequest("POST", authUrl, bytes.NewBufferString(v.Encode()))
	if err != nil {
		return nil, err
	}

	cs.cookieJar, _ = cookiejar.New(nil)

	resp, err := cs.RoundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return resp, backends.ErrAuthorizationFailed
	}

	if rc := resp.Cookies(); len(rc) > 0 {
		log.Info("Setting cookie (%s): %s", req.URL, rc)
		cs.cookieJar.SetCookies(req.URL, rc)
	}

	resp.StatusCode = 302
	resp.Header.Set("Location", fmt.Sprintf("/mail/FEWebmail.html?isCustomLogin=true&remote_user=%s", email))
	return resp, nil
}

func (cs *LdapBackendSession) RoundTrip(r *http.Request) (*http.Response, error) {
	if cs.email == "" {
		// for unauthenticated users
		return cs.RoundTripper.RoundTrip(r)
	}

	if r.URL.Path == "/mail/WebmailLogin.html" {
		cs.cookieJar = nil
	}

	if resp, err := cs.Authenticate(cs.email); err != nil {
		return resp, err
	} else if resp != nil {
		return resp, err
	}

	for _, cookie := range cs.cookieJar.Cookies(r.URL) {
		r.AddCookie(cookie)
	}

	resp, err := cs.RoundTripper.RoundTrip(r)
	if err != nil {
		return resp, err
	}

	if rc := resp.Cookies(); len(rc) > 0 {
		cs.cookieJar.SetCookies(r.URL, rc)
	}

	return resp, err
}

func (cs *LdapBackendSession) DialTLS(network, address string) (net.Conn, error) {
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

type LdapBackendSession struct {
	http.RoundTripper
	email     string
	c         *LdapBackend
	cookieJar http.CookieJar
}

func (h *LdapBackend) Host(host string) string {
	if v, ok := h.Mapping[host]; ok {
		return v
	}
	return host
}

func (h *LdapBackend) NewSession(email string) (http.RoundTripper, error) {
	email = "innotest@forfarmers.eu"

	if cs, ok := h.sessions[email]; ok {
		return cs, nil
	}

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

	// todo: add sync
	h.sessions[email] = cs
	return cs, nil
}

func (b *LdapBackend) Password(email string) string {
	h := sha1.New()

	// todo password in config
	h.Write([]byte(fmt.Sprintf("%s%s", email, "SUPERGEHEIM")))

	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}

func (b *LdapBackend) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	log.Debug("Bind %s %s", bindDN, bindSimplePw)
	//l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", h.ldapServer, h.ldapPort))
	// l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "172.20.1.20", 389))
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", "172.20.1.20", 636), nil)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}

	if err := l.Bind(bindDN, bindSimplePw); err != nil {
		return ldap.LDAPResultOperationsError, err
	}

	b.ldap = l

	// check bindSimplePw == b.Password(email)
	//return ldap.LDAPResultInvalidCredentials, nil
	return ldap.LDAPResultSuccess, nil
}

func (b *LdapBackend) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	log.Debug("Search %s %#v", boundDN, searchReq)
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
	return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil

	/*
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
		}, nil*/
	// return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (b *LdapBackend) Close(boundDn string, conn net.Conn) error {
	if b.ldap != nil {
		b.ldap.Close()
	}

	return nil
}
