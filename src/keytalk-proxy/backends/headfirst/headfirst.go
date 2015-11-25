package headfirst

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"keytalk-proxy/backends"
	"net"
	"net/http"
	"os"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("headfirst")

const sessionToken = "service_ticket"
const host = "dev-select.headfirst.nl:443"
const authUrl = "https://dev-select.headfirst.nl/api/v2/user/login"
const usernameKey = "username"
const passwordKey = "password"

var tlsConfig = &tls.Config{
	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
}

type Headfirst struct {
	credentials backends.Credentials
}

// Dial
// Authorize
// HeadfirstSession
// maybe have a http(s) base handler

type BackendConn struct {
	net.Conn
}

func (h *Headfirst) Dial(email string) (net.Conn, error) {
	return tls.Dial("tcp", host, tlsConfig)
}

func (h *Headfirst) Handle(token string, outconn net.Conn, req *http.Request) (*http.Response, error) {
	var err error
	req.Host = host

	if token != "" {
		if _, err := req.Cookie("XSRF-TOKEN"); err == http.ErrNoCookie {
			req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
		}

		req.Header.Set("X-XSRF-TOKEN", token)
	} else {
		log.Debug("No token found, using anonymous.")
	}

	if err = req.Write(outconn); err != nil {
		return nil, err
	}

	r := bufio.NewReader(outconn)

	resp, err := http.ReadResponse(r, req)
	// TODO: remove XSRF-TOKEN cookie from response
	return resp, err
}

func (h *Headfirst) Authenticate(email string) (string, error) {
	c := h.credentials

	c.Lock()
	defer c.Unlock()

	email = "zp"

	if token, err := c.DB.Get(email); err != nil {
		return token, nil
	}

	buffer := new(bytes.Buffer)
	err2 := json.NewEncoder(buffer).Encode(map[string]interface{}{
		usernameKey: email,
		passwordKey: "password", // Let's talk about how to gen passwords from this
	})

	req2, err2 := http.NewRequest("POST", authUrl, buffer)
	if err2 != nil {
		return "", err2
	}

	setHeaders(req2)

	resp2, err2 := http.DefaultClient.Do(req2)
	if err2 != nil {
		return "", err2
	}

	if resp2.StatusCode == 200 {
		authResponse := map[string]interface{}{}
		err2 = json.NewDecoder(io.TeeReader(resp2.Body, os.Stdout)).Decode(&authResponse)
		if err2 != nil {
			return "", err2
		}

		token := authResponse[sessionToken].(string)

		c.DB.Set(email, token)

		return token, nil
	} else {
		return "", backends.ErrAuthorizationFailed
	}
}

func setHeaders(r *http.Request) {
	r.Header.Set("Accept", "application/json, text/plain, */*")
	r.Header.Set("Accept-Encoding", "Encoding:gzip, deflate")
	r.Header.Set("Connection", "close")
	r.Header.Set("Content-Type", "application/json;charset=UTF-8")
}

var _ = backends.Register([]string{
	"headfirst-select.lvh.me",
	"headfirst-select.devkeytalk.com",
}, register())

func register() backends.Creator {
	return func() backends.Backend {
		db, err := backends.NewDB()
		if err != nil {
			log.Fatal(err)
		}
		return &Headfirst{
			credentials: backends.Credentials{
				DB: db,
			},
		}
	}
}
