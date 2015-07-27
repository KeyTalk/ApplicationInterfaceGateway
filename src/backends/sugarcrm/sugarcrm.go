package sugarcrm

import (
	"backends"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	"golang.org/x/net/publicsuffix"
)

const sessionToken = "PHPSESSID"
const host = "sas.opacus.co.uk"
const authUrl = "http://sas.opacus.co.uk/index.php"
const usernameKey = "user_name"
const passwordKey = "user_password"

var ErrRedirect = errors.New("redirect")
var jarOptions = &cookiejar.Options{
	PublicSuffixList: publicsuffix.List,
}
var client = &http.Client{}

var tlsConfig = &tls.Config{
	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
}

type SugarCRM struct {
	credentials backends.Credentials
	sync.Mutex
}

func (s *SugarCRM) Handle(tlscon *tls.Conn, clientCert *x509.Certificate, req *http.Request) {
	var email string
	var err error

	req2 := req

	if clientCert != nil {
		email = clientCert.Subject.CommonName
		_, err = s.authenticate(email)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	req2.Host = host
	req2.RequestURI = ""
	req2.URL.Scheme = "http"
	req2.URL.Host = host

	req2.URL.RawQuery = req2.URL.Query().Encode()
	v := url.Values{}
	v.Add("module", "Opportunities")
	v.Add("action", "index")
	req2.URL.RawQuery = v.Encode()

	fmt.Println(req2.URL.RawQuery)

	req2.Form = v
	req2.PostForm = v

	resp2, err2 := client.Do(req2)

	if err2 != nil {
		fmt.Println(err2)
		return
	}

	resp2.Write(tlscon)
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

	resp2, _ := client.PostForm(authUrl, v)

	if resp2.StatusCode == 200 {
		return "", nil
	} else {
		return "", errors.New("Authorization failure")
	}
}

func init() {
	backends.Add("opacus.lvh.me", func() backends.Backend {
		jar, _ := cookiejar.New(jarOptions)
		client.Jar = jar
		return &SugarCRM{
			credentials: backends.Credentials{
				DB: map[string]*string{},
			},
		}
	})
}
