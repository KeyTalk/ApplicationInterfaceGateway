package sugarcrm

import (
	"backends"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const sessionToken = "PHPSESSID"
const host = "sas.opacus.co.uk:80"
const authUrl = "http://sas.opacus.co.uk/index.php"
const usernameKey = "user_name"
const passwordKey = "user_password"

var tlsConfig = &tls.Config{
	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
}

type SugarCRM struct {
	credentials backends.Credentials
}

func (s *SugarCRM) Handle(tlscon *tls.Conn, clientCert *x509.Certificate, req *http.Request) {
	var email string
	var token string
	var err error

	if clientCert != nil {
		email = clientCert.Subject.CommonName
		token, err = s.authenticate(email)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	req.Host = host
	req.Header.Set("Connection", "close")
	outconn, err := net.Dial("tcp", host)
	defer outconn.Close()
	if err != nil {
		fmt.Println("failed to connect: " + err.Error())
		return
	}
	fmt.Println(token)
	if token != "" {
		req.Header.Set("Cookie", token)
	}

	req.Write(outconn)

	r := bufio.NewReader(outconn)
	resp, err := http.ReadResponse(r, req)
	if resp == nil {
		return
	}

	resp.Write(tlscon)
}

func (s *SugarCRM) authenticate(email string) (string, error) {
	s.credentials.Lock()
	defer s.credentials.Unlock()

	if token, ok := s.credentials.DB[email]; ok {
		return *token, nil
	}

	v := url.Values{}
	v.Add("module", "Users")
	v.Add("action", "Authenticate")
	v.Add("Login", "Log In")
	v.Add(usernameKey, email)
	v.Add(passwordKey, "opacus")

	fmt.Println(v)

	fmt.Println("posting")
	resp2, err2 := http.PostForm(authUrl, v)

	if err2 != nil {
		return "", err2
	}
	fmt.Println(resp2)
	if resp2.StatusCode == 200 {
		header := resp2.Header["Set-Cookie"][0]
		token := strings.Split(header, ";")[0]
		s.credentials.DB[email] = &token

		return token, nil
	} else {
		return "", errors.New("Authorization failure")
	}
}

func init() {
	backends.Add("opacus.lvh.me", func() backends.Backend {
		return &SugarCRM{
			credentials: backends.Credentials{
				DB: map[string]*string{},
			},
		}
	})
}
