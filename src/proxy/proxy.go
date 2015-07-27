package proxy

import (
	"backends"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("api")

var (
	ErrBackendNotFound = errors.New("Backend not found")
)

type Server struct {
	ListenerString        string `toml:"listener"`
	ServerCertificateFile string `toml:"server_cert"`
	ServerKeyFile         string `toml:"server_key"`
	Backends              map[string]backends.Backend

	listener net.Listener
}

func (s *Server) Start(bs map[string]backends.Creator) {
	// support for multiple certificates and SNI, multiple protocols
	cert, err := tls.LoadX509KeyPair(s.ServerCertificateFile, s.ServerKeyFile)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	s.Backends = map[string]backends.Backend{}
	for k, v := range bs {
		s.Backends[k] = v()
	}

	config := tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequestClientCert,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}

	listener, err := tls.Listen("tcp", s.ListenerString, &config)
	s.listener = listener
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	log.Info("Keytalk proxy: started\n")
	s.listenAndServe()
}

func (s *Server) listenAndServe() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Error("server: accept: %s", err)
			break
		}
		log.Info("server: accepted from %s", conn.RemoteAddr())
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	tlscon, ok := conn.(*tls.Conn)
	if !ok {
		log.Error("Could not type assert tls.Conn")
		return
	}
	defer tlscon.Close()

	if err := tlscon.Handshake(); err != nil {
		log.Error("server: handshake failed: %s. Continuing anonymously.\n", err.Error())
	}

	var clientCert *x509.Certificate = nil
	for _, v := range tlscon.ConnectionState().PeerCertificates {
		if !v.IsCA {
			clientCert = v
		}
	}

	// get request params
	reader := bufio.NewReader(tlscon)
	req, err := http.ReadRequest(reader)
	if req == nil {
		return
	}

	backend, err := s.fetchBackend(req.Host)
	if err != nil {
		log.Error(err.Error())

		resp := &http.Response{
			Header:     make(http.Header),
			Request:    req,
			StatusCode: http.StatusOK,
		}
		resp.Header.Set("Content-Type", "Application / json")

		body := "Error"

		resp.Body = ioutil.NopCloser(strings.NewReader(body))

		resp.Write(tlscon)
		return
	}

	backend.Handle(tlscon, clientCert, req)
}

func (s *Server) fetchBackend(host string) (backends.Backend, error) {
	if backend, ok := s.Backends[host]; ok {
		return backend, nil
	}
	return nil, ErrBackendNotFound
}
