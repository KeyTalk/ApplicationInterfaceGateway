package backends

import (
	"net/http"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("backend")

type Backend interface {
	NewSession(string) (http.RoundTripper, error)
	Host(string) string
}
