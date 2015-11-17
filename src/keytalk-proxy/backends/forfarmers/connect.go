package forfarmers

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"keytalk-proxy/backends"
	_ "log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/spacemonkeygo/openssl"
)

type Connect struct {
	credentials backends.Credentials
}

// Dial
// Authorize
// HeadfirstSession
// maybe have a http(s) base handler

func (h *Connect) Dial() (net.Conn, error) {
	cfg := client.Config{
		Endpoints: []string{"http://127.0.0.1:2379"},
		Transport: client.DefaultTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	c, err := client.New(cfg)
	if err != nil {
		fmt.Println(err.Error())
	}
	kapi := client.NewKeysAPI(c)

	var certstr []byte
	var keystr []byte

	resp2, err := kapi.Get(context.Background(), "/foo", nil)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		certstr = []byte(resp2.Node.Value)
	}

	resp2, err = kapi.Get(context.Background(), "/foo2", nil)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		keystr = []byte(resp2.Node.Value)
	}

	if len(keystr) == 0 {
		fmt.Println("Connect Handle")

		data, err := ioutil.ReadFile("certs/ca.pem")
		if err != nil {
			return nil, err
		}

		var caCert *x509.Certificate
		var caprivateKey interface{}

		for {
			pemBlock, rest := pem.Decode(data)
			if pemBlock == nil {
				break
			}

			fmt.Println(pemBlock.Type)

			if pemBlock.Type == "RSA PRIVATE KEY" {
				caprivateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
				if err != nil {
					return nil, err
				}
			}

			if pemBlock.Type == "CERTIFICATE" {
				caCert, err = x509.ParseCertificate(pemBlock.Bytes)
				if err != nil {
					return nil, err
				}
			}
			data = rest
		}

		/*
			data, err = ioutil.ReadFile("/tmp/bla.txt")
			if err != nil {
				return err
			}

			for {
				pemBlock, rest := pem.Decode(data)
				if pemBlock == nil {
					break
				}

				if pemBlock.Type == "CERTIFICATE" {
					cert, err := x509.ParseCertificate(pemBlock.Bytes)
					if err != nil {
						return err
					}
					fmt.Printf("cert: %#v", cert)
				}
				data = rest
			}
		*/

		var notBefore time.Time

		notBefore = time.Now()
		notAfter := notBefore.Add(365 * 24 * time.Hour)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		extSubjectAltName := pkix.Extension{}
		extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
		extSubjectAltName.Critical = false
		extSubjectAltName.Value = []byte(`otherName:msUPN;UTF8:innotest, email:innotest@forfarmers.eu`)

		template := x509.Certificate{
			SerialNumber: serialNumber,
			NotBefore:    notBefore,
			NotAfter:     notAfter,

			PublicKeyAlgorithm: x509.RSA,
			SignatureAlgorithm: x509.SHA1WithRSA,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			Issuer: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "NL"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "Default City"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Default Company Ltd"}},
			},
			Subject: pkix.Name{
				ExtraNames: []pkix.AttributeTypeAndValue{
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "local"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "Forfarmers"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "NL"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Lochem"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Extern"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Innovice IT"},
					pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Innotest/emailAddress=innotest@forfarmers.eu"},
				},
			},
			ExtraExtensions: []pkix.Extension{
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []uint8{0x3, 0x2, 0x5, 0xe0}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: []uint8{0x30, 0x20, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x4, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x2}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: false, Value: []uint8{0x30, 0x0}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: false, Value: []uint8{0x30, 0x16, 0x80, 0x14, 0x77, 0x32, 0xf5, 0xe1, 0xf6, 0x1d, 0xdf, 0x7b, 0xf3, 0x49, 0xe3, 0xfd, 0xbe, 0x72, 0xba, 0xe6, 0xce, 0x5f, 0xd1, 0x63}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Critical: false, Value: []uint8{0x30, 0x28, 0x30, 0x26, 0xa0, 0x24, 0xa0, 0x22, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x30, 0x32, 0x2e, 0x31, 0x35, 0x32, 0x3a, 0x38, 0x31, 0x2f, 0x63, 0x61, 0x2e, 0x63, 0x72, 0x6c}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Critical: false, Value: []uint8{0x4, 0x14, 0x89, 0x4f, 0x62, 0xc4, 0x3e, 0x92, 0x3, 0x2, 0x7b, 0xff, 0x96, 0x92, 0xf4, 0x5b, 0xfc, 0x8f, 0xbc, 0x89, 0x4c, 0xa4}},
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false, Value: []uint8{0x30, 0x32, 0xa0, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x3, 0xa0, 0xa, 0xc, 0x8, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x81, 0x16, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}},
			},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{
				asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
			},
			CRLDistributionPoints: []string{"http://192.168.102.152:81/ca.crl"},
		}

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		_ = caprivateKey

		fmt.Println("GEN")
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, priv.Public(), caprivateKey)
		if err != nil {
			return nil, err
		}

		cert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		pem.Encode(os.Stdout, cert)
		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		pem.Encode(os.Stdout, key)

		crt, err := tls.X509KeyPair(pem.EncodeToMemory(cert), pem.EncodeToMemory(key))
		if err != nil {
			return nil, err
		}

		_ = crt
		certstr = pem.EncodeToMemory(cert)
		resp2, err := kapi.Set(context.Background(), "/foo", string(certstr), nil)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			// print common key info
			fmt.Printf("Set is done. Metadata is %q\n", resp2)
		}

		keystr = pem.EncodeToMemory(key)
		resp2, err = kapi.Set(context.Background(), "/foo2", string(keystr), nil)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			// print common key info
			fmt.Printf("Set is done. Metadata is %q\n", resp2)
		}

		pool := x509.NewCertPool()
		pool.AddCert(caCert)
	}
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// load client certificate

	cert99, err := openssl.LoadCertificateFromPEM(certstr)

	pk99, err := openssl.LoadPrivateKeyFromPEM(keystr) // pem.EncodeToMemory(key))

	ctx.UseCertificate(cert99)

	ctx.UsePrivateKey(pk99)

	ctx.SetVerifyMode(openssl.VerifyNone)

	conn, err := openssl.Dial("tcp", "127.0.0.1:8443", ctx, openssl.InsecureSkipHostVerification)
	if err != nil {
		panic(err)
	}
	err = conn.Handshake()
	if err != nil {
		panic(err)
	}
	return conn, err
}

// https://github.com/jmckaskill/gontlm/blob/master/nhttp/http.go

var encBase64 = base64.StdEncoding.EncodeToString
var decBase64 = base64.StdEncoding.DecodeString

// TODO: RoundTrip?

func (h *Connect) Handle(token string, outconn net.Conn, req *http.Request) (*http.Response, error) {

	/*
		tlsConfig := &tls.Config{
			//Certificates: []tls.Certificate{crt},
			//ClientCAs:    pool,
			//NextProtos: []string{"http/1.1"},
			NextProtos: []string{},
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS12,
			ServerName: "tconnect.forfarmers.eu",
		}*/
	dump, _ := httputil.DumpRequestOut(req, false)
	fmt.Println("Request", string(dump))
	fmt.Printf("%#v", req)
	fmt.Printf("%#v", *req.URL)

	req.Host = "tconnect.forfarmers.eu"

	if err := req.Write(outconn); err == io.EOF {
		return nil, err
	} else if err != nil {
		panic(err)
		return nil, err
	}

	var resp *http.Response
	reader2 := bufio.NewReader(outconn)
	resp, err := http.ReadResponse(reader2, req)
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		panic(err)
		return nil, err
	}

	/*
		res, err := transport.RoundTrip(req)
		if err != nil {
			// p.logf("http: proxy error: %v", err)
			// rw.WriteHeader(http.StatusInternalServerError)
			return nil, err
		}
	*/

	dump, _ = httputil.DumpResponse(resp, false)
	fmt.Println("Response", string(dump))

	return resp, err
	/*

		if err != nil {
			panic(err)
		}
			_ = conn

			err = conn.Handshake()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Conn %#v\n", conn)
			req, err := http.NewRequest("GET", "https://tconnect.forfarmers.eu/UK/Pages/Default.aspx", nil)
			if err != nil {
				panic(err)
			}
			fmt.Println("TEST2")

			if err = req.Write(conn); err == io.EOF {
				return nil
			} else if err != nil {
				panic(err)
				return err
			}

			fmt.Println("TEST1")

			var resp *http.Response
			reader2 := bufio.NewReader(conn)
			resp, err = http.ReadResponse(reader2, req)
			if err == io.EOF {
				return nil
			} else if err != nil {
				panic(err)
				return err
			}

			fmt.Println("TEST4")
			b, err := ioutil.ReadAll(reader2)
			if err != nil {
				panic(err)
			}

			fmt.Println("TEST5")
			fmt.Printf("%#v", resp)

			fmt.Println(string(b))
			return

			tlsConfig := &tls.Config{
				//Certificates: []tls.Certificate{crt},
				//ClientCAs:    pool,
				//NextProtos: []string{"http/1.1"},
				NextProtos: []string{},
				MinVersion: tls.VersionTLS10,
				MaxVersion: tls.VersionTLS12,
				ServerName: "tconnect.forfarmers.eu",
			}

			transport := &http.Transport{TLSClientConfig: tlsConfig}
			client := &http.Client{Transport: transport}

			fmt.Printf("BLA 1 ")
			// Do GET something
			resp, err = client.Get(h) //"https://127.0.0.1:8443")
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			fmt.Printf("BLA 2 %#v--", resp)

			// Dump response
			data, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			fmt.Println("BLA 3", data)

			return nil
			// load ca
			// generate new certificate
			// sign
			// sign

	*/
}

/*
func (h *Connect) Handle(token string, outconn net.Conn, req *http.Request) (*http.Response, error) {
	var err error
	req.Host = "connect.forfarmers.eu"

	req.URL.Host = "connect.forfarmers.eu"
	req.URL.Scheme = "https"

	req.Header.Set("Host", "connect.forfarmers.eu")

	/req.Header.Set("Accept", "application/json, text/plain, *")
	/req.Header.Set("Accept-Encoding", "Encoding:gzip, deflate")
	req.Header.Set("Connection", "close")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encBase64([]byte("innotest:Bej1a3OM"))))

	dump, _ := httputil.DumpRequestOut(req, true)
	fmt.Println(string(dump))

	transport := http.DefaultTransport
	transport.(*http.Transport).DialTLS = func(network, addr string) (net.Conn, error) {
		return tls.Dial("tcp", "connect.forfarmers.eu:443", tlsConfig)
	}

	negotiator := ntlmssp.Negotiator{transport}

	resp, err := negotiator.RoundTrip(req)

	*
		dump, _ = httputil.DumpResponse(resp, true)
		fmt.Println(string(dump))
	*

	return resp, err
}
*/

func (h *Connect) Authenticate(email string) (string, error) {
	fmt.Println(email)
	return "", nil
}

var _ = backends.Register([]string{
	"connect.forfarmers.lvh.me",
	"connect.forfarmers.dev",
}, func() backends.Backend {
	db, err := backends.NewDB()
	if err != nil {
		fmt.Println(err)
	}

	return &Connect{
		credentials: backends.Credentials{
			DB: db,
		},
	}
})
