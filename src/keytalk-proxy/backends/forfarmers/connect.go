package forfarmers

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"keytalk-proxy/backends"
	_ "log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/spacemonkeygo/openssl"
)

type Connect struct {
	credentials backends.Credentials
}

// https://github.com/jmckaskill/gontlm/blob/master/nhttp/http.go
// TODO: RoundTrip?

// Dial
// Authorize
// HeadfirstSession
// maybe have a http(s) base handler
type CacheManager struct {
	client.KeysAPI
}

func (cm *CacheManager) GetBytes(key string) ([]byte, error) {
	resp, err := cm.KeysAPI.Get(context.Background(), key, nil)
	if err != nil {
		return nil, err
	}

	return []byte(resp.Node.Value), nil
}

func (cm *CacheManager) Set(key string, val interface{}) error {
	var s string
	switch val.(type) {
	case *pem.Block:
		s = string(pem.EncodeToMemory(val.(*pem.Block)))
	}

	_, err := cm.KeysAPI.Set(context.Background(), key, s, &client.SetOptions{TTL: time.Hour * 12})
	return err
}

func NewCacheManager() (*CacheManager, error) {
	cfg := client.Config{
		Endpoints: []string{"http://127.0.0.1:2379"},
		Transport: client.DefaultTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}

	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	kapi := client.NewKeysAPI(c)

	return &CacheManager{
		kapi,
	}, nil
}

type CertificateManager struct {
	ca struct {
		PrivateKey  *rsa.PrivateKey
		Certificate *x509.Certificate
	}
}

func (cm *CertificateManager) loadCA() error {
	data, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		return err
	}

	for {
		pemBlock, rest := pem.Decode(data)
		if pemBlock == nil {
			break
		}

		if pemBlock.Type == "RSA PRIVATE KEY" {
			if cm.ca.PrivateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err != nil {
				return err
			}
		}

		if pemBlock.Type == "CERTIFICATE" {
			if cm.ca.Certificate, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
				return err
			}
		}

		data = rest
	}
	return nil
}

func (cm *CertificateManager) GenerateCRL() ([]byte, error) {
	if err := cm.loadCA(); err != nil {
		return nil, err
	}

	now := time.Now()
	expiry := now.AddDate(0, 1, 0)
	derBytes, err := cm.ca.Certificate.CreateCRL(rand.Reader, cm.ca.PrivateKey, []pkix.RevokedCertificate{}, now, expiry)
	if err != nil {
		return nil, err
	}

	crl := &pem.Block{Type: "X509 CRL", Bytes: derBytes}

	certstr := pem.EncodeToMemory(crl)
	return certstr, nil
}

func (cm *CertificateManager) Generate(email string) ([]byte, *rsa.PrivateKey, error) {
	if err := cm.loadCA(); err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(12 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA1WithRSA,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "local"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "Forfarmers"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "NL"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Lochem"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Extern"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Innovice IT"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: email},
			},
		},
		ExtraExtensions: []pkix.Extension{
		/*
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []uint8{0x3, 0x2, 0x5, 0xe0}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: []uint8{0x30, 0x20, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x2, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x4, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x2}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: false, Value: []uint8{0x30, 0x0}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: false, Value: []uint8{0x30, 0x16, 0x80, 0x14, 0x77, 0x32, 0xf5, 0xe1, 0xf6, 0x1d, 0xdf, 0x7b, 0xf3, 0x49, 0xe3, 0xfd, 0xbe, 0x72, 0xba, 0xe6, 0xce, 0x5f, 0xd1, 0x63}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Critical: false, Value: []uint8{0x30, 0x28, 0x30, 0x26, 0xa0, 0x24, 0xa0, 0x22, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x30, 0x32, 0x2e, 0x31, 0x35, 0x32, 0x3a, 0x38, 0x31, 0x2f, 0x63, 0x61, 0x2e, 0x63, 0x72, 0x6c}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Critical: false, Value: []uint8{0x4, 0x14, 0x89, 0x4f, 0x62, 0xc4, 0x3e, 0x92, 0x3, 0x2, 0x7b, 0xff, 0x96, 0x92, 0xf4, 0x5b, 0xfc, 0x8f, 0xbc, 0x89, 0x4c, 0xa4}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false, Value: []uint8{0x30, 0x32, 0xa0, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x3, 0xa0, 0xa, 0xc, 0x8, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x81, 0x16, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}},
		*/
		},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
		},
		CRLDistributionPoints: []string{"http://192.168.102.152/ca.crl"},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.ca.Certificate, priv.Public(), cm.ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, priv, nil

}

func NewCertificateManager() (*CertificateManager, error) {
	return &CertificateManager{}, nil
}

func (h *Connect) Dial(email string) func(network, address string) (net.Conn, error) {
	cema, err := NewCertificateManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	cm, err := NewCacheManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	certstr, _ := cm.GetBytes(fmt.Sprintf("connect.forfarmers.eu:%s:cert", email))

	keystr, _ := cm.GetBytes(fmt.Sprintf("connect.forfarmers.eu:%s:key", email))

	if len(keystr) == 0 {
		derBytes, priv, err := cema.Generate(email)
		if err != nil {
			fmt.Println(err.Error())
			return nil
		}

		cert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		certstr = pem.EncodeToMemory(cert)
		if err := cm.Set(fmt.Sprintf("connect.forfarmers.eu:%s:cert", email), cert); err != nil {
			fmt.Println(err.Error())
			return nil
		}

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		keystr = pem.EncodeToMemory(key)
		if err := cm.Set(fmt.Sprintf("connect.forfarmers.eu:%s:key", email), key); err != nil {
			fmt.Println(err.Error())
		}
	}

	fmt.Printf("email %s\n%s\n%s\n", email, keystr, certstr)

	return func(network, address string) (net.Conn, error) {

		fmt.Printf("Dialing %s %s\n", network, address)

		ctx, err := openssl.NewCtx()
		if err != nil {
			log.Error("Error creating openssl ctx: %s", err.Error())
			return nil, err
		}

		cert99, err := openssl.LoadCertificateFromPEM(certstr)
		if err != nil {
			log.Error("Error creating openssl ctx: %s", err.Error())
			return nil, err
		}

		ctx.UseCertificate(cert99)

		pk99, err := openssl.LoadPrivateKeyFromPEM(keystr)
		if err != nil {
			log.Error("Error creating openssl ctx: %s", err.Error())
			return nil, err
		}

		ctx.UsePrivateKey(pk99)

		ctx.SetVerifyMode(openssl.VerifyNone)

		//conn, err := openssl.Dial("tcp", "127.0.0.1:8443", ctx, openssl.InsecureSkipHostVerification)
		conn, err := openssl.Dial("tcp", "172.20.0.133:443", ctx, openssl.InsecureSkipHostVerification)
		if err != nil {
			log.Error("Error dialing: %s", err.Error())
			return nil, err
		}

		host, _, err := net.SplitHostPort(address)

		if err = conn.SetTlsExtHostName(host); err != nil {
			log.Error("Error set tls ext host: %s", err.Error())
			return nil, err
		}

		conn.SetDeadline(time.Now().Add(time.Minute * 10))

		err = conn.Handshake()
		if err != nil {
			log.Error("Error handshake: %s", err.Error())
			return nil, err
		}
		return conn, err
	}
}

func (h *Connect) Handle(token string, outconn net.Conn, req *http.Request) (*http.Response, error) {
	dump, _ := httputil.DumpRequestOut(req, false)
	fmt.Printf("Request: %s\n", string(dump))

	req.Host = "tconnect.forfarmers.eu"

	// TODO
	// req.Header.Set("X-Forwarded-For", req.

	if err := req.Write(outconn); err != nil {
		log.Debug("req.Write(outconn) %s", err.Error())
		return nil, err
	}

	r := bufio.NewReader(outconn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		log.Debug("resp.Read(outconn) %s", err.Error())
		return nil, err
	}

	resp.Header.Get("Location")

	dump, _ = httputil.DumpResponse(resp, false)
	log.Debug("Response: %s\n", string(dump))

	return resp, err
}

func (h *Connect) Authenticate(email string) (string, error) {
	fmt.Println(email)
	return "", nil
}

// return transport roundtripper
// https://github.com/golang/go/blob/f78a4c84ac8ed44aaf331989aa32e40081fd8f13/src/net/http/filetransport.go<Paste>

var _ = backends.Register([]string{
	"connect.forfarmers.lvh.me",
	"connect.forfarmers.dev",
	"tconnect.forfarmers.eu",
	"tconnect.forfarmers.devkeytalk.com",
	"my.test.connect.forfarmers.eu",
	"connect.forfarmers.eu",
	"myconnect.forfarmers.eu",
	"projects.forfarmers.eu",
}, func() backends.Backend {
	return &Connect{}
})
