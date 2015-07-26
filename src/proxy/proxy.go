package proxy

import (
	"backends"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
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
		ClientAuth:         tls.RequireAnyClientCert,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}

	listener, err := tls.Listen("tcp", s.ListenerString, &config)
	s.listener = listener
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	log.Printf("Keytalk proxy: started\n")
	s.listenAndServe()
}

func (s *Server) listenAndServe() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	tlscon, ok := conn.(*tls.Conn)
	if !ok {
		fmt.Println("Could not type assert tls.Conn")
		return
	}
	defer tlscon.Close()

	if err := tlscon.Handshake(); err != nil {
		log.Printf("server: handshake failed: %s\n", err)
		return
	}

	var clientCert *x509.Certificate = nil
	for _, v := range tlscon.ConnectionState().PeerCertificates {
		clientCert = v
	}

	// get request params
	reader := bufio.NewReader(tlscon)
	req, err := http.ReadRequest(reader)
	if req == nil {
		return
	}

	backend, err := s.fetchBackend(req.Host)
	if err != nil {
		fmt.Println("err")
	}

	backend.Handle(tlscon, clientCert, req)
}

func (s *Server) fetchBackend(host string) (backends.Backend, error) {
	subdomain := strings.Split(host, ".")[0]
	return s.Backends[subdomain], nil
}
