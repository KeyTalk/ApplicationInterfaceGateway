package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

var tlsConfig = &tls.Config{
	ClientSessionCache: tls.NewLRUClientSessionCache(1024),
}

type Server struct {
	ListenerString        string              `toml:"listener"`
	ServerCertificateFile string              `toml:"server_cert"`
	ServerKeyFile         string              `toml:"server_key"`
	Backends              map[string]*Backend `toml:"backends"`

	listener net.Listener
}

func (s *Server) Start() {
	s.initializeBackends()
	// support for multiple certificates and SNI, multiple protocols
	cert, err := tls.LoadX509KeyPair(s.ServerCertificateFile, s.ServerKeyFile)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
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

	email := clientCert.Subject.CommonName
	var token string

	if clientCert != nil {
		token, err = backend.CredentialsStore.Get(email)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	req.Host = backend.Host
	req.Header.Set("Connection", "close")

	outconn, err := tls.Dial("tcp", backend.ToString(), tlsConfig)
	defer outconn.Close()
	if err != nil {
		fmt.Println("failed to connect: " + err.Error())
		return
	}

	req.Header.Set("Cookie", "TGT=%7B%22ticket_granting_ticket%22%3Anull%2C%22username%22%3A%22anonymous%2B28375%40headfirstselect.nl%22%7D; _iqnomyvid=2379422251; _iqnomyfid=57; AWSELB=7557A7131E7486D92AD42C94AF245454D3B6A4D043CA9D594E96F64853509E2C57E1054A8F21FFE2191481871F2B0914BB31987EE5FE7468A1575FC8B2299A4081EA6BA119; _gat=1; __utmt=1; __utma=235694494.1113251712.1427145564.1434468736.1434479534.12; __utmb=235694494.1.10.1434479534; __utmc=235694494; __utmz=235694494.1430478279.6.4.utmcsr=172.16.2.225|utmccn=(referral)|utmcmd=referral|utmcct=/; JSESSIONID=1E0B536E5841B859F35AF528461CA64C; _ga=GA1.2.1113251712.1427145564; XSRF-TOKEN="+token)
	req.Header.Set("X-XSRF-TOKEN", token)
	req.Write(outconn)

	r := bufio.NewReader(outconn)
	resp, err := http.ReadResponse(r, req)
	if resp == nil {
		return
	}

	resp.Write(tlscon)
}

func (s *Server) fetchBackend(host string) (*Backend, error) {
	subdomain := strings.Split(host, ".")[0]
	return s.Backends[subdomain], nil
}

func (s *Server) initializeBackends() {
	for _, backend := range s.Backends {
		backend.CredentialsStore = NewCredentials(backend)
	}
}
