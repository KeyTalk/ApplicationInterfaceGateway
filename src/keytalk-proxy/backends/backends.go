package backends

import (
	"net"
	"net/http"
	"sync"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("backend")

type BackendSession interface {
	Dial(email string) func(network, address string) (net.Conn, error)
	// DialTLS(email string) func(network, address string) (net.Conn, error)
	// TODO: should Authenticate return a new session? The session will handle the traffic
	Authenticate(email string) (string, error)
	Handle(string, net.Conn, *http.Request) (*http.Response, error)
}

type Backend interface {
	NewSession(string) (http.RoundTripper, error)
	Host(string) string
}

type Creator func() Backend

var Backends = map[string]Creator{}
var Hosts = map[string]Backend{}

func Register(hosts []string, creator Creator) Creator {
	for _, host := range hosts {
		log.Info("Registered backend for: %s", host)
		Backends[host] = creator
	}

	return creator
}

func Register2(t string, creator Creator) Creator {
	log.Info("Registered service for: %s", t)
	Backends[t] = creator
	return creator
}

func add(hosts []string, creator Creator) {
}

type Credentials struct {
	DB *DB
	sync.Mutex
}
