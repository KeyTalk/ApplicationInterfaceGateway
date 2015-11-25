package forfarmers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"keytalk-proxy/backends"
	"net"
	"net/http"
	"net/http/cookiejar"

	"github.com/op/go-logging"
)

var cookieJar http.CookieJar

var log = logging.MustGetLogger("forfarmers")

const sessionToken = "service_ticket"
const host = "quarantine.forfarmers.eu:443"
const authUrl = "https://quarantine.forfarmers.eu:443/module/webmail.fe"
const usernameKey = "username"
const passwordKey = "password"

var tlsConfig = &tls.Config{

	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	InsecureSkipVerify: true,
}

type Quarantine struct {
	credentials backends.Credentials
}

// Dial
// Authorize
// HeadfirstSession
// maybe have a http(s) base handler

type BackendConn struct {
	net.Conn
}

func (h *Quarantine) Dial(email string) (net.Conn, error) {
	return tls.Dial("tcp", host, tlsConfig)
}

func (h *Quarantine) Handle(token string, outconn net.Conn, req *http.Request) (*http.Response, error) {
	var err error
	req.Host = host

	req.URL.Host = host
	req.URL.Scheme = "https"
	log.Info("CookieURL:", req.URL)

	for _, cookie := range cookieJar.Cookies(req.URL) {
		req.AddCookie(cookie)
		log.Info("Adding cookie", cookie)
	}

	if err = req.Write(outconn); err != nil {
		return nil, err
	}

	r := bufio.NewReader(outconn)

	resp, err := http.ReadResponse(r, req)
	// TODO: remove XSRF-TOKEN cookie from response
	return resp, err
}

func (h *Quarantine) Authenticate(email string) (string, error) {
	c := h.credentials

	c.Lock()
	defer c.Unlock()

	email = "zp"

	if cookieJar != nil {
		return "token", nil
	}

	if token, err := c.DB.Get(email); err != nil {
		//return token, nil
		_ = token
	}

	buffer := new(bytes.Buffer)
	buffer.WriteString("name=innotest%40forfarmers.eu&password=Bej1a3OM&CutomizeLogin=Sign+In&reqAction=1&reqObject=WMLogin")

	req2, err2 := http.NewRequest("POST", authUrl, buffer)
	if err2 != nil {
		log.Info("Authenticate", err2)
		return "", err2
	}

	cookieJar, _ = cookiejar.New(nil)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Jar: cookieJar,
	}

	resp2, err2 := client.Do(req2)
	if err2 != nil {
		log.Info("Authenticate", err2)
		return "", err2
	}

	log.Info("%#v", resp2)

	if resp2.StatusCode != 200 {
		return "", backends.ErrAuthorizationFailed
	}

	log.Info("%#v", cookieJar)
	return "", nil
}

func setHeaders(r *http.Request) {
	r.Header.Set("Accept", "application/json, text/plain, */*")
	r.Header.Set("Accept-Encoding", "Encoding:gzip, deflate")
	r.Header.Set("Connection", "close")
	r.Header.Set("Content-Type", "application/json;charset=UTF-8")
}

var _ = backends.Register([]string{
	"quarantine.forfarmers.lvh.me",
	"quarantine.forfarmers.dev",
}, register())

func register() backends.Creator {
	return func() backends.Backend {
		db, err := backends.NewDB()
		if err != nil {
			log.Fatal(err)
		}

		return &Quarantine{
			credentials: backends.Credentials{
				DB: db,
			},
		}
	}
}
