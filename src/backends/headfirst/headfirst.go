package headfirst

import (
	"backends"
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
)

const sessionToken = "service_ticket"
const host = "dev-select.headfirst.nl:443"
const authUrl = "https://dev-select.headfirst.nl/api/v2/user/login"
const usernameKey = "username"
const passwordKey = "password"

var tlsConfig = &tls.Config{
	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
}

type Headfirst struct {
	credentials struct {
		db map[string]string
		sync.Mutex
	}
}

func (h *Headfirst) Handle(tlscon *tls.Conn, clientCert *x509.Certificate, req *http.Request) {
	email := clientCert.Subject.CommonName
	var token string
	var err error

	if clientCert != nil {
		token, err = h.authenticate(email)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	req.Host = host
	req.Header.Set("Connection", "close")

	outconn, err := tls.Dial("tcp", host, tlsConfig)
	defer outconn.Close()
	if err != nil {
		fmt.Println("failed to connect: " + err.Error())
		return
	}

	req.Header.Set("Cookie", "TGT=%7B%22ticket_granting_ticket%22%3Anull%2C%22username%22%3A%22anonymous%2B28375%40headfirstselect.nl%22%7D; _iqnomyvid=2379422251; _iqnomyfid=57; AWSELB=7557A7131E7486D92AD42C94AF245454D3B6A4D043CA9D594E96F64853509E2C57E1054A8F21FFE2191481871F2B0914BB31987EE5FE7468A1575FC8B2299A4081EA6BA119; _gat=1; __utmt=1; __utma=235694494.1113251712.1427145564.1434468736.1434479534.12; __utmb=235694494.1.10.1434479534; __utmc=235694494; __utmz=235694494.1430478279.6.4.utmcsr=172.16.2.225|utmccn=(referral)|utmcmd=referral|utmcct=/; JSESSIONID=1E0B536E5841B859F35AF528461CA64C; _ga=GA1.2.1113251712.1427145564; XSRF-TOKEN="+token)
	req.Header.Set("X-XSRF-TOKEN", token)
	req.Write(outconn)

	r := bufio.NewReader(outconn)
	resp, err := http.ReadResponse(r, req)
	if resp == nil {
		return
	}

	resp.Write(tlscon)
}

func (h *Headfirst) authenticate(email string) (string, error) {
	c := h.credentials

	c.Lock()
	defer c.Unlock()

	if token, ok := c.db[email]; ok {
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

		c.db[email] = token

		return token, nil
	} else {
		return "", errors.New("Authorization failure")
	}
}

func setHeaders(r *http.Request) {
	r.Header.Set("Accept", "application/json, text/plain, */*")
	r.Header.Set("Accept-Encoding", "Encoding:gzip, deflate")
	r.Header.Set("Connection", "close")
	r.Header.Set("Content-Type", "application/json;charset=UTF-8")
}

func init() {
	backends.Add("headfirst", func() backends.Backend {
		return &Headfirst{
			credentials: struct {
				db map[string]string
				sync.Mutex
			}{
				db: map[string]string{},
			},
		}
	})
}
