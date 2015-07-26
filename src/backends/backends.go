package backends

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"
)

type Backend interface {
	Handle(*tls.Conn, *x509.Certificate, *http.Request)
}

type Creator func() Backend

var Backends = map[string]Creator{}

func Add(name string, creator Creator) {
	Backends[name] = creator
}

type Credentials struct {
	DB map[string]string
	sync.Mutex
}
