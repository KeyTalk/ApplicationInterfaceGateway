package backends

import (
	"net"
	"net/http"
	"sync"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("backend")

type Backend interface {
	Dial() (net.Conn, error)
	// TODO: should Authenticate return a new session? The session will handle the traffic
	Authenticate(email string) (string, error)
	Handle(string, net.Conn, *http.Request) (*http.Response, error)
}

type Creator func() Backend

var Backends = map[string]Creator{}

func Add(hosts []string, creator Creator) {
	for _, host := range hosts {
		log.Info("Registered backend for: %s", host)
		Backends[host] = creator
	}
}

type Credentials struct {
	DB map[string]*string
	sync.Mutex
}
