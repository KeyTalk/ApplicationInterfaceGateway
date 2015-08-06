package proxy

import (
	"backends"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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
	CACertificateFile     string `toml:"ca_cert"`
	ServerCertificateFile string `toml:"server_cert"`
	ServerKeyFile         string `toml:"server_key"`
	Backends              map[string]backends.Backend
	cert                  tls.Certificate
	listener              net.Listener
}

func (s *Server) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Debug("Certificate request for %s", clientHello.ServerName)
	return &s.cert, nil
}

func (s *Server) Start(bs map[string]backends.Creator) {
	var err error
	if s.cert, err = tls.LoadX509KeyPair(s.ServerCertificateFile, s.ServerKeyFile); err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	s.Backends = map[string]backends.Backend{}
	for k, v := range bs {
		s.Backends[k] = v()
	}

	caBytes, err := ioutil.ReadFile(s.CACertificateFile)
	if err != nil {
		log.Fatalf("could not load ca file %s: %s", s.CACertificateFile, err)
	}

	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("could not parse ca file %s", s.CACertificateFile)
	}

	// workaround to enum registered CA's, certs in certpool are private
	caPoolCustom := NewCertPool()
	if ok := caPoolCustom.AppendCertsFromPEM(caBytes); !ok {
		log.Fatalf("could not parse ca file %s", s.CACertificateFile)
	}

	for _, cert := range caPoolCustom.Certs() {
		log.Info("Loaded CA: %s", cert.Subject.CommonName)
	}

	config := tls.Config{
		ClientCAs:      caPool,
		Certificates:   []tls.Certificate{s.cert},
		GetCertificate: s.GetCertificate,
		// ClientAuth:   tls.RequireAnyClientCert,
		ClientAuth: tls.RequireAndVerifyClientCert,
		// ClientAuth:         tls.RequestClientCert,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}

	// TODO: listen and redirect on 80
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

	reader := bufio.NewReader(tlscon)

	var req *http.Request
	var err error

	defer func() {
		if err == nil {
			return
		} else if err == io.EOF {
			return
		}

		log.Error("Error: ", err.Error())

		resp := &http.Response{
			Header:     make(http.Header),
			Request:    req,
			StatusCode: http.StatusUnauthorized,
		}

		resp.Header.Set("Content-Type", "application/json")

		body := err.Error()

		resp.Body = ioutil.NopCloser(strings.NewReader(body))

		resp.Write(tlscon)
	}()

	if err := tlscon.Handshake(); err == io.EOF {
		err = nil
		return
	} else if err != nil {
		log.Error("server: handshake failed: %s. Continuing anonymously.\n", err.Error())
	}

	var clientCert *x509.Certificate = nil
	for _, v := range tlscon.ConnectionState().PeerCertificates {
		if v.IsCA {
			continue
		}

		clientCert = v
	}

	req, err = http.ReadRequest(reader)
	if err != nil {
		return
	}

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	log.Info("Request for host %s and path %s.", host, req.URL.String())

	backend, err := s.fetchBackend(host)
	if err != nil {
		return
	}

	token := ""
	subject := ""
	if clientCert != nil {
		subject = clientCert.Subject.CommonName
		if token, err = backend.Authenticate(subject); err != nil {
			return
		}
	}

	clientconn, err := backend.Dial()
	defer clientconn.Close()

	for {
		var resp *http.Response
		if resp, err = backend.Handle(token, clientconn, req); err != nil {
			return
		}

		if err = resp.Write(tlscon); err != nil {
			return
		}

		log.Info("%s %s %s %d %s %s", req.Host, req.URL.String(), req.Header.Get("Content-Type"), resp.StatusCode, subject, req.Header.Get("Referer"))

		// for keep alive, next request
		req, err = http.ReadRequest(reader)
		if err == io.EOF {
			return
		} else if err != nil {
			return
		}

		// log.Debug("Keep-Alive connection")
	}
}

func (s *Server) fetchBackend(host string) (backends.Backend, error) {
	if backend, ok := s.Backends[host]; ok {
		return backend, nil
	}
	return nil, ErrBackendNotFound
}
