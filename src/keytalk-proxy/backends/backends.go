package backends

import (
	"net"
	"net/http"
	"sync"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("backend")

type Backend interface {
	Dial(email string) func(network, address string) (net.Conn, error)
	// TODO: should Authenticate return a new session? The session will handle the traffic
	Authenticate(email string) (string, error)
	Handle(string, net.Conn, *http.Request) (*http.Response, error)
}

type Creator func() Backend

var Backends = map[string]Creator{}

func Register(hosts []string, creator Creator) Creator {
	for _, host := range hosts {
		log.Info("Registered backend for: %s", host)
		Backends[host] = creator
	}

	return creator
}

func add(hosts []string, creator Creator) {
}

type Credentials struct {
	DB *DB
	sync.Mutex
}
