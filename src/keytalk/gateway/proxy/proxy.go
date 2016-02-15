package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"

	"keytalk/gateway/backends"

	"github.com/BurntSushi/toml"
	"github.com/PuerkitoBio/ghost/handlers"
	"github.com/gorilla/mux"
	"github.com/kr/pretty"
	"github.com/spacemonkeygo/openssl"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("proxy")

var (
	ErrBackendNotFound = errors.New("Backend not found")
)

type Creator func(*Server) backends.Backend

var hosts = map[string]backends.Backend{}

var Backends = map[string]Creator{}

func Register(t string, creator Creator) Creator {
	Backends[t] = creator
	return creator
}

type Server struct {
	ListenerString        string   `toml:"listener"`
	TLSListenerString     string   `toml:"tlslistener"`
	CACertificateFile     string   `toml:"ca_cert"`
	ServerCertificateFile string   `toml:"server_cert"`
	ServerKeyFile         string   `toml:"server_key"`
	AuthType              string   `toml:"authenticationtype"`
	Logging               *Logging `toml:"logging"`

	Services map[string]toml.Primitive `toml:"services"`

	CertificateManager *backends.CertificateManager `toml:"certificate-manager"`
	CacheManager       *backends.CacheManager

	listener net.Listener
	template *template.Template
}

type Service struct {
	Type    string   `toml:"type"`
	Backend string   `toml:"backend"`
	Hosts   []string `toml:"hosts"`
}

func New(configFile string) *Server {
	server := &Server{}

	md, err := toml.DecodeFile(configFile, server)
	if err != nil {
		panic(err)
	}

	server.template = template.Must(template.New("index.html").Parse(`Keytalk gateway error <br/><b>{{ .error }}</b>`))

	server.CacheManager, err = backends.NewCacheManager()
	if err != nil {
		log.Fatal("Could not create cache manager: %s.", err.Error())
	}

	for _, service := range server.Services {
		s := Service{}
		if err := md.PrimitiveDecode(service, &s); err != nil {
			panic(err)
		}

		creator, ok := Backends[s.Type]
		if !ok {
			log.Info("Could not find backend %s.\n", s.Type)
			continue
		}

		backend := creator(server)
		if err := md.PrimitiveDecode(service, backend); err != nil {
			panic(err)
		}

		for _, host := range s.Hosts {
			log.Info("Registered host %s with backend %s.\n", host, s.Type)
			hosts[host] = backend
		}
	}

	return server
}

func (s *Server) Serve() {
	s.startRedirector()
	s.startEtcd()

	ctx, err := openssl.NewCtxFromFiles(s.ServerCertificateFile, s.ServerKeyFile)
	if err != nil {
		log.Fatal("Ctx", err.Error())
	}

	log.Debug("Loading CA certificate: %s", s.CACertificateFile)
	err = ctx.LoadVerifyLocations(s.CACertificateFile, "")
	if err != nil {
		log.Fatal("loadVer", err.Error())
	}

	err = ctx.SetClientCAListFromFile(s.CACertificateFile)
	if err != nil {
		log.Fatal("SetClientCA", err.Error())
	}

	ctx.SetTLSExtServernameCallback(func(ssl *openssl.SSL) openssl.SSLTLSExtErr {
		//	pretty.Print("TLSExtServernameCallback", ssl)
		/*
			http://stackoverflow.com/questions/5113333/how-to-implement-server-name-indication-sni

			Set up an additional SSL_CTX() for each different certificate;
			Add a servername callback to each SSL_CTX() using SSL_CTX_set_tlsext_servername_callback();
			In the callback, retrieve the client-supplied servername with SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name). Figure out the right SSL_CTX to go with that host name, then switch the SSL object to that SSL_CTX with SSL_set_SSL_CTX().
			The s_client.c and s_server.c files in the apps/ directory of the OpenSSL source distribution implement this functionality, so they're a good resource to see how it should be done.

			const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
			printf("ServerName: %s\n", servername);
		*/
		log.Debug("SNI: %s", ssl.GetServername())
		return openssl.SSLTLSExtErrOK
	})

	ctx.SetSessionCacheMode(openssl.SessionCacheServer)
	ctx.SetSessionId([]byte{1})
	// ctx.SetVerifyMode(openssl.VerifyPeer /*| openssl.VerifyFailIfNoPeerCert*/)

	ctx.SetVerify(openssl.VerifyPeer|openssl.VerifyClientOnce, func(ok bool, store *openssl.CertificateStoreCtx) bool {
		pretty.Print("VerifyCallback", store)
		return true
	})

	listener, err := openssl.Listen("tcp4", s.TLSListenerString, ctx)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	s.listener = listener

	log.Info("Keytalk Gateway: started\n")
	s.listenAndServe()
}

func (s *Server) startRedirector() {
	go func() {
		r := mux.NewRouter()

		r.HandleFunc("/ca.crl", func(w http.ResponseWriter, r *http.Request) {
			buff, err := s.CertificateManager.GenerateCRL()
			if err != nil {
				log.Error("Error: %s", err.Error())
				return
			}

			w.Write(buff)
			return
		})

		r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("Redirecting http to https (http://%s/%s)", r.Host, r.RequestURI)
			http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.RequestURI), 301)
		})

		s := &http.Server{
			Addr:    s.ListenerString,
			Handler: handlers.LogHandler(r, handlers.NewLogOptions(log.Info, "_default_")),
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

		log.Error("Error while handling request: ", err.Error())

		var buff bytes.Buffer
		if err = s.template.Execute(&buff, map[string]interface{}{
			"error": err.Error(),
		}); err != nil {
			log.Error("Could not write error response: ", err.Error())
			return
		}

		// show error page
		resp := &http.Response{
			Header:     make(http.Header),
			Request:    req,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			StatusCode: http.StatusUnauthorized,
		}

		resp.Header.Set("Server", "Keytalk Gateway")
		resp.Header.Set("Content-Type", "text/html")
		resp.Body = ioutil.NopCloser(&buff)
		// defer resp.Body.Close()

		resp.Write(tlscon)
	}()

	if err := tlscon.Handshake(); err == io.EOF {
		err = nil
		return
	} else if err != nil {
		// log.Error("server: handshake failed: %s. Continuing anonymously.\n", err.Error())
		return
	}

	req, err = http.ReadRequest(reader)
	if err != nil {
		return
	}

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	backend, err := s.fetchBackend(host)
	if err != nil {
		return
	}

	subjectName := ""

	cert, err := tlscon.PeerCertificate()
	if err == nil {
		subject, err := cert.GetSubjectName()
		if err != nil {
			return
		}

		commonName := ""
		if s, ok := subject.GetEntry(openssl.NID_commonName); ok {
			commonName = s
		}

		parts := strings.Split(commonName, "\\")
		if len(parts) != 2 {
			err = fmt.Errorf("Invalid subject name format %s", commonName)
			return
		}

		subjectName = parts[1]
	}

	t, err := backend.NewSession(subjectName)
	if err != nil {
		return
	}

	for {
		req.Host = backend.Host(host)

		req.URL = &url.URL{
			Scheme:   "https",
			Host:     req.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
			Fragment: req.URL.Fragment,
		}

		// req.Header.Del("Accept-Encoding")

		dump, _ := httputil.DumpRequest(req, false)
		log.Debug("Request: %s", string(dump))

		var resp *http.Response
		if resp, err = t.RoundTrip(req); err == io.EOF {
		} else if err != nil {
			err = fmt.Errorf("Error occured during roundtrip: %s", err.Error())
			return
		}

		switch resp.StatusCode {
		case 301:
			// TODO: rewrite location urls
		case 403:
			// TODO: try to sign in again
		}

		// resp.Body = NewChangeStream(resp.Body)

		dump, _ = httputil.DumpResponse(resp, false)
		if err = resp.Write(tlscon); err != nil {
			return
		}

		// TODO: add apache compatible format
		log.Info("%s %s %s %d %s %s", req.Host, req.URL.String(), req.Header.Get("Content-Type"), resp.StatusCode, subjectName, req.Header.Get("Referer"))

		// implement Close / non keep alives as well
		// for keep alive, next request
		req, err = http.ReadRequest(reader)
		if err != nil {
			break
		}
	}
}

func (s *Server) fetchBackend(host string) (backends.Backend, error) {
	if backend, ok := hosts[host]; ok {
		return backend, nil
	}
	return nil, ErrBackendNotFound
}
