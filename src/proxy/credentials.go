package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
)

type Credentials struct {
	backend *Backend
	db      map[string]string
	sync.Mutex
}

func NewCredentials(b *Backend) *Credentials {
	return &Credentials{
		backend: b,
		db:      map[string]string{},
	}
}

func (c *Credentials) Get(email string) (string, error) {
	c.Lock()
	defer c.Unlock()

	if token, ok := c.db[email]; ok {
		return token, nil
	}

	buffer := new(bytes.Buffer)
	err2 := json.NewEncoder(buffer).Encode(map[string]interface{}{
		c.backend.UsernameKey: email,
		c.backend.PasswordKey: "password", // Let's talk about how to gen passwords from this
	})

	req2, err2 := http.NewRequest("POST", c.backend.AuthURL, buffer)

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

		token := authResponse[c.backend.SessionToken].(string)

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
