package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"

	"keytalk-proxy/backends"

	"github.com/BurntSushi/toml"
	"github.com/PuerkitoBio/ghost/handlers"
	"github.com/gorilla/mux"
	"github.com/spacemonkeygo/openssl"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("proxy")

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
	TLSListenerString     string `toml:"tlslistener"`
	CACertificateFile     string `toml:"ca_cert"`
	ServerCertificateFile string `toml:"server_cert"`
	ServerKeyFile         string `toml:"server_key"`
	AuthType              string `toml:"authenticationtype"`
	Logging               []struct {
		Output string `toml:"output"`
		Level  string `toml:"level"`
	} `toml:"logging"`

	// Backends              map[string]backends.Backend
	cert     tls.Certificate
	listener net.Listener
	Services map[string]toml.Primitive `toml:"Services"`
	cema     *backends.CertificateManager
}

type Service struct {
	Type    string   `toml:"type"`
	Backend string   `toml:"backend"`
	Hosts   []string `toml:"hosts"`
}

/*
func (s *Service) UnmarshalTOML(p interface{}) {
		s.Type, _ = data["type"].(string)
		s.Backend, _ = data["backend"].(string)

		m.Hosts = make([]string)
		dishes := data["dishes"].(map[string]interface{})
		for n, v := range dishes {
			if d, ok := v.(map[string]interface{}); ok {
				nd := dish{}
				nd.UnmarshalTOML(d)
				m.Dishes[n] = nd
			} else {
				return fmt.Errorf("not a dish")
			}
		}

}
*/

func (s *Server) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Debug("Certificate request for %s", clientHello.ServerName)
	return &s.cert, nil
}

func (s *Server) Start(bs map[string]backends.Creator) {
	/*
		cema, err := forfarmers.NewCertificateManager()
		if err != nil {
			fmt.Println(err.Error())
			return
		}


		derBytes, priv, err := cema.Generate("innotest")
		if err != nil {
			log.Fatal(err)
		}

		cert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		certstr := pem.EncodeToMemory(cert)

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		keystr := pem.EncodeToMemory(key)
		if err != nil {
			log.Fatal(err)
		}

			fmt.Println(string(certstr))
			fmt.Println(string(keystr))

			// b, _ := asn1.Marshal(asn1.RawValue{Tag: 0, Class: 2, Bytes: []byte("innotest, email:innotest@forfarmers.eu")})
			b, _ := asn1.Marshal(asn1.RawValue{Tag: 0, Class: 2, Bytes: []byte("msUPN;UTF8:innotest, email:innotest@forfarmers.eu")})

			fmt.Printf("%x\n", b)

			rest := []byte{0x30, 0x43, 0xa0, 0x29, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03, 0xa0, 0x1b, 0x0c, 0x19, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x46, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x81, 0x16, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}

			bla2, err := marshalSANs([]otherName{otherName{Method: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, Location: asn1.RawValue{Tag: 0, Class: 2, Bytes: []byte("innotest@Forfarmers.local")}}}, []string{}, []string{"innotest@forfarmers.eu"}, []net.IP{})
			fmt.Printf("Marshalled %x %#v\n", bla2, err)

			var v asn1.RawValue
			//var err error
			rest, err = asn1.Unmarshal(rest, &v)

			rest = v.Bytes
			// rest := []byte{0x30, 0x32, 0xa0, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x3, 0xa0, 0xa, 0xc, 0x8, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x81, 0x16, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}
			fmt.Printf("Rest %x", rest)
			for len(rest) > 0 {
				var v asn1.RawValue
				// var err error
				rest, err = asn1.Unmarshal(rest, &v)
				if err != nil {
					fmt.Printf("%#v", err.Error())
					break
				}

				fmt.Printf("Tag: %d %d %d %#v %s\n\n", v.Tag, v.Class, len(v.Bytes), v.Bytes, string(v.Bytes))
				// rest = v.Bytes

				switch v.Tag {
				case 0:
					rest2 := v.Bytes

					var ID asn1.ObjectIdentifier
					rest2, _ = asn1.Unmarshal(rest2, &ID)
					fmt.Printf("REMCO %#v\n\n%#v\n", 0, ID)

					var rv asn1.RawValue
					rest2, _ = asn1.Unmarshal(rest2, &rv)
					fmt.Printf("REMCO %#v\n\n%#v\n%s\n", 0, rv, string(rv.Bytes))
				case 1:
					fmt.Printf("Email: %s", string(v.Bytes))
					/*
							emailAddresses = append(emailAddresses, string(v.Bytes))
						case 2:
							dnsNames = append(dnsNames, string(v.Bytes))
						case 7:
							switch len(v.Bytes) {
							case net.IPv4len, net.IPv6len:
								ipAddresses = append(ipAddresses, v.Bytes)
							default:
								err = errors.New("x509: certificate contained IP address of length " + strconv.Itoa(len(v.Bytes)))
								return
							}
						}*
				}

			}
			return

			var subjectAltName struct {
				V asn1.RawValue
				/*
					R1 struct {
					} `asn1,tag:0`
	*/
	//MaxPathLen int `asn1:"default:-1"`
	// ID         asn1.ObjectIdentifier
	//MaxPathLen1 int `asn1:"default:-1"`
	//	MaxPathLen2 int `asn1:"default:-1"`
	//	MaxPathLen3 int `asn1:"default:-1"`
	// V          asn1.RawValue
	// X          asn1.RawValue
	//B []byte `asn1:"set"`
	/*
		MaxPathLen  int `asn1:"optional,default:-1"`
		MaxPathLen1 int `asn1:"optional,default:-1"`

		ID asn1.ObjectIdentifier
	*/
	// 	B []byte `asn1:"optional"`
	/*
				R1 struct {
					Value interface{} `asn1:"set"`
				} `asn1:"optional,tag:1"`
					Value []byte
					Raw asn1.RawValue `asn1:"optional,tag:0"`

			*
		}
		_ = subjectAltName

		rest2 := []uint8{0x30, 0x43, 0xa0, 0x29, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03, 0xa0, 0x1b, 0x0c, 0x19, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x46, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x81, 0x16, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}
		rest, x := asn1.Unmarshal(rest2[0:], &subjectAltName)
		fmt.Printf("REMCOB %#v\n\n%#v\n", x, subjectAltName)

		rest2 = subjectAltName.V.Bytes
		var ID asn1.ObjectIdentifier
		var rv asn1.RawValue

		rest, x = asn1.Unmarshal(rest2, &ID)
		fmt.Printf("REMCO %#v\n\n%#v\n", x, ID)

		rest, x = asn1.Unmarshal(rest, &rv)
		fmt.Printf("REMCO %#v\n\n%#v\n%s\n", x, rv, string(rv.Bytes))

		rest, x = asn1.Unmarshal(rest, &rv)
		fmt.Printf("REMCO %#v\n\n%#v\n%s\n", x, rv, string(rv.Bytes))
		fmt.Printf("Rest %x", rest)
	*/

	/*
		s.Backends = map[string]backends.Backend{}
		for k, v := range bs {
			s.Backends[k] = v()
		}
	*/

	s.startRedirector()
	s.startEtcd()

	var err error
	s.cema, err = backends.NewCertificateManager()
	if err != nil {
		log.Fatal(err)
	}

	// var err error

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
	ctx.SetSessionCacheMode(openssl.SessionCacheServer)

	ctx.SetSessionId([]byte{1})
	ctx.SetVerifyMode(openssl.VerifyPeer | openssl.VerifyFailIfNoPeerCert)
	/*
		ctx.SetVerify(openssl.VerifyPeer|openssl.VerifyFailIfNoPeerCert, func(ok bool, store *openssl.CertificateStoreCtx) bool {
			fmt.Printf("Verify certificate: %#v", *store)
			return true
		})
	*/

	listener, err := openssl.Listen("tcp4", s.TLSListenerString, ctx)
	s.listener = listener
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}

	log.Info("Keytalk proxy: started\n")
	s.listenAndServe()
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("Redirecting http to https (http://%s/%s)", r.Host, r.RequestURI)
	http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.RequestURI), 301)
}

func (s *Server) startRedirector() {
	go func() {
		r := mux.NewRouter()

		r.HandleFunc("/ca.crl", func(w http.ResponseWriter, r *http.Request) {

			buff, err := s.cema.GenerateCRL()
			if err != nil {
				log.Error("Error: %s", err.Error())
				return
			}

			w.Write(buff)
			return
		})

		r.NotFoundHandler = http.HandlerFunc(RedirectHandler)

		s := &http.Server{
			Addr:    s.ListenerString,
			Handler: handlers.LogHandler(r, handlers.NewLogOptions(log.Info, "_default_")),
		}

		log.Fatal(s.ListenAndServe())
	}()
}

func NewChangeStream(r io.ReadCloser) io.ReadCloser {
	return &ChangeStream{r, []byte{}}
}

type ChangeStream struct {
	io.ReadCloser

	// being used for temporarily rest, when being replaced with longer
	overflow []byte
}

func (cs *ChangeStream) Read(p []byte) (n int, err error) {
	copy(p, cs.overflow)

	n, err = cs.ReadCloser.Read(p[len(cs.overflow):])
	if err == io.EOF {
	} else if err != nil {
		return n, err
	}

	cs.overflow = []byte{}

	needle := []byte("srvnllobot.forfarmers.local")

	repl := []byte("bo-t-nl.forfarmers.eu")

	// currently we are assuming:
	for i := 0; i < n-len(needle); i++ {
		if bytes.Compare(p[i:i+len(needle)], needle) != 0 {
			continue
		}

		newIndex := i

		// take care of longer, sizes, put in rest buffer.
		for j := 0; j < len(repl); j++ {
			p[newIndex] = repl[j]
			newIndex++
		}

		oldIndex := i + len(needle)
		for oldIndex < n {
			p[newIndex] = p[oldIndex]
			oldIndex++
			newIndex++
		}

		n = newIndex
	}

	return n, err
}

func (cs *ChangeStream) Close() error {
	return cs.ReadCloser.Close()
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

		log.Error("Error: ", err.Error())

		resp := &http.Response{
			Header:     make(http.Header),
			Request:    req,
			StatusCode: http.StatusUnauthorized,
		}

		resp.Header.Set("Server", "Keytalk Authentication Proxy")

		body := fmt.Sprintf("Keytalk proxy error: %s", err.Error())

		r := strings.NewReader(body)
		resp.Body = ioutil.NopCloser(r)

		resp.Write(tlscon)
	}()

	if err := tlscon.Handshake(); err == io.EOF {
		err = nil
		return
	} else if err != nil {
		log.Error("server: handshake failed: %s. Continuing anonymously.\n", err.Error())
		return
	}

	cert, err := tlscon.PeerCertificate()
	if err != nil {

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

	commonName := ""
	if cert == nil {
		// err
		return
	}

	subject, err := cert.GetSubjectName()
	if err != nil {
		log.Error(err.Error())
		return
	}

	if s, ok := subject.GetEntry(openssl.NID_commonName); ok {
		commonName = s
	}

	t, err := backend.NewSession(commonName)
	if err != nil {
		log.Error(err.Error())
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

		req.Header.Del("Accept-Encoding")

		dump, _ := httputil.DumpRequest(req, false)
		log.Debug("Request: %s", string(dump))

		var resp *http.Response
		if resp, err = t.RoundTrip(req); err != nil {
			return
		}

		switch resp.StatusCode {
		case 301:
			// TODO: rewrite location urls
		case 403:
			// TODO: try to sign in again
		}

		resp.Body = NewChangeStream(resp.Body)

		dump, _ = httputil.DumpResponse(resp, false)
		if err = resp.Write(tlscon); err != nil {
			return
		}

		// TODO: add apache compatible format
		log.Info("%s %s %s %d %s %s", req.Host, req.URL.String(), req.Header.Get("Content-Type"), resp.StatusCode, commonName, req.Header.Get("Referer"))

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
	if backend, ok := backends.Hosts[host]; ok {
		return backend, nil
	}
	return nil, ErrBackendNotFound
}
