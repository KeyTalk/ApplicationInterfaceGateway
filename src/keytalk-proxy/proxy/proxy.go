package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"strings"

	"keytalk-proxy/backends"

	"github.com/spacemonkeygo/openssl"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("api")

var (
	ErrBackendNotFound = errors.New("Backend not found")
)

type ClientAuthType struct {
	tls.ClientAuthType
}

func (d *ClientAuthType) UnmarshalTOML(data []byte) error {
	switch string(data) {
	case "request":
		d.ClientAuthType = tls.RequestClientCert
	case "require-any":
		d.ClientAuthType = tls.RequireAnyClientCert
	case "verify-given":
		d.ClientAuthType = tls.VerifyClientCertIfGiven
	case "require-verify-given":
		d.ClientAuthType = tls.RequireAndVerifyClientCert
	default:
		return fmt.Errorf("Unknown auth type: %s", string(data))

	}
	return nil
}

type Server struct {
	ListenerString        string `toml:"listener"`
	CACertificateFile     string `toml:"ca_cert"`
	ServerCertificateFile string `toml:"server_cert"`
	ServerKeyFile         string `toml:"server_key"`
	AuthType              string `toml:"authenticationtype"`
	Backends              map[string]backends.Backend
	cert                  tls.Certificate
	listener              net.Listener
}

func (s *Server) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Debug("Certificate request for %s", clientHello.ServerName)
	return &s.cert, nil
}

func (s *Server) Start(bs map[string]backends.Creator) {

	s.Backends = map[string]backends.Backend{}
	for k, v := range bs {
		s.Backends[k] = v()
	}

	/*
		var err error
		if s.cert, err = tls.LoadX509KeyPair(s.ServerCertificateFile, s.ServerKeyFile); err != nil {
			log.Fatalf("server: loadkeys: %s", err)
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

	*/
	startRedirector()

	s.startEtcd()

	var err error

	ctx, err := openssl.NewCtxFromFiles(s.ServerCertificateFile, s.ServerKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	err = ctx.LoadVerifyLocations(s.CACertificateFile, "")
	if err != nil {
		log.Fatal(err)
	}

	listener, err := openssl.Listen("tcp4", s.ListenerString, ctx)

	//listener, err := tls.Listen("tcp4", s.ListenerString, &config)
	s.listener = listener
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	log.Info("Keytalk proxy: started\n")
	s.listenAndServe()
}

func RedirectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Redirecting http to https (http://%s/%s)", r.Host, r.RequestURI)
		http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.RequestURI), 301)
		return
	}
}

func startRedirector() {
	go func() {
		s := &http.Server{
			Addr:    fmt.Sprintf(":%s", "8081"),
			Handler: RedirectHandler(),
		}

		log.Fatal(s.ListenAndServe())
	}()
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
	if err := recover(); err != nil {
		trace := make([]byte, 1024)
		count := runtime.Stack(trace, true)
		log.Error("Error: %s", err)
		log.Debug("Stack of %d bytes: %s\n", count, trace)
		return
	}

	defer conn.Close()

	tlscon, ok := conn.(*openssl.Conn)
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

		resp.Header.Set("Server", "Keytalk Authentication Proxy")

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
	/*
		for _, v := range tlscon.ConnectionState().PeerCertificates {
			if v.IsCA {
				continue
			}

			clientCert = v
		}
	*/

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
	if clientCert != nil || true {
		subject = "test"
		// subject = clientCert.Subject.CommonName
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

		switch resp.StatusCode {
		case 301:
			// TODO: rewrite location urls
		case 403:
			// TODO: try to sign in again
		}

		if err = resp.Write(tlscon); err != nil {
			return
		}

		log.Info("%s %s %s %d %s %s", req.Host, req.URL.String(), req.Header.Get("Content-Type"), resp.StatusCode, subject, req.Header.Get("Referer"))
		// TODO: add apache compatible format

		// for keep alive, next request
		req, err = http.ReadRequest(reader)
		if err == io.EOF {
			return
		} else if err != nil {
			return
		}
	}
}

func (s *Server) fetchBackend(host string) (backends.Backend, error) {
	if backend, ok := s.Backends[host]; ok {
		return backend, nil
	}
	return nil, ErrBackendNotFound
}
