package forfarmers

import (
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
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/op/go-logging"
	"github.com/spacemonkeygo/openssl"
)

var log = logging.MustGetLogger("forfarmers")

type Proxy struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`
}

type Connect struct {
	Backend string            `toml:"backend"`
	Hosts   []string          `toml:"hosts"`
	Mapping map[string]string `toml:"mapping"`

	cema *CertificateManager
	cama *CacheManager
}
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

type otherName struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(otherNames []otherName, dnsNames, emailAddresses []string, ipAddresses []net.IP) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range otherNames {
		b1, _ := asn1.Marshal(name.Method)
		b2, _ := asn1.Marshal(name.Location)
		b2, _ = asn1.Marshal(asn1.RawValue{Tag: 0x0, Class: 2, IsCompound: true, Bytes: b2})
		rawValues = append(rawValues, asn1.RawValue{Tag: 0, Class: 2, Bytes: append(b1, b2...), IsCompound: true})
	}
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	return asn1.Marshal(rawValues)
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

	subjectAltName, err := marshalSANs(
		[]otherName{otherName{
			Method:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
			Location: asn1.RawValue{Tag: 0xC, Class: 0x0, Bytes: []byte("nstri@Forfarmers.local")}}},
		[]string{},
		[]string{email},
		[]net.IP{},
	)

	fmt.Printf("SubjectAltName: %x\n", subjectAltName)

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
																											           80316d7355504e3b555446383a 696e6e6f74657374 2c20656d61696c3a, 0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false, Value: []uint8{0x30, 0x32, 0xa0, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x14, 0x2, 0x3, 0xa0, 0xa, 0xc, 0x8,
				0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74,
				0x81,
				0x16,
				0x69, 0x6e, 0x6e, 0x6f, 0x74, 0x65, 0x73, 0x74, 0x40, 0x66, 0x6f, 0x72, 0x66, 0x61, 0x72, 0x6d, 0x65, 0x72, 0x73, 0x2e, 0x65, 0x75}},
				8026
				696e6e6f74657374
				2c20656d61696c3a
				696e6e6f7465737440666f726661726d6572732e6575

				80316d7355504e3b555446383a 696e6e6f74657374 2c20656d6 1696c3a696e6e6f7465737440666f726661726d6572732e6575
			*/
			//			pkix.Extension{Id: []int{2, 5, 29, 17}, Value: asn1.RawValue{Tag: 0, Class: 2, Bytes: []byte("")}},
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: subjectAltName},
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

func (cs *ConnectSession) RoundTrip(r *http.Request) (*http.Response, error) {
	return cs.RoundTripper.RoundTrip(r)

}

func (cs *ConnectSession) DialTLS(network, address string) (net.Conn, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	cert99, err := openssl.LoadCertificateFromPEM(cs.certstr)
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	ctx.UseCertificate(cert99)

	pk99, err := openssl.LoadPrivateKeyFromPEM(cs.keystr)
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	ctx.UsePrivateKey(pk99)

	ctx.SetSessionCacheMode(openssl.SessionCacheClient)

	ctx.SetSessionId([]byte{1})

	ctx.SetVerifyMode(openssl.VerifyNone)

	conn, err := openssl.Dial("tcp", cs.c.Backend, ctx, openssl.InsecureSkipHostVerification)
	if err != nil {
		log.Error("Error dialing: %s", err.Error())
		return nil, err
	}

	host, _, err := net.SplitHostPort(address)

	host = cs.c.Host(host)

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

type ConnectSession struct {
	http.RoundTripper
	email   string
	certstr []byte
	keystr  []byte
	c       *Connect
}

func (cs *ProxySession) DialTLS(network, address string) (net.Conn, error) {
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Error("Error creating openssl ctx: %s", err.Error())
		return nil, err
	}

	ctx.SetSessionCacheMode(openssl.SessionCacheClient)

	ctx.SetSessionId([]byte{1})

	ctx.SetVerifyMode(openssl.VerifyNone)

	conn, err := openssl.Dial("tcp", cs.c.Backend, ctx, openssl.InsecureSkipHostVerification)
	if err != nil {
		log.Error("Error dialing: %s", err.Error())
		return nil, err
	}

	host, _, err := net.SplitHostPort(address)

	host = cs.c.Host(host)

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

type ProxySession struct {
	http.RoundTripper
	c *Proxy
}

func (h *Connect) Host(host string) string {
	if v, ok := h.Mapping[host]; ok {
		return v
	}
	return host
}

func (h *Connect) NewSession(email string) (http.RoundTripper, error) {

	certstr, _ := h.cama.GetBytes(fmt.Sprintf("connect.forfarmers.eu:%s:cert", email))

	keystr, _ := h.cama.GetBytes(fmt.Sprintf("connect.forfarmers.eu:%s:key", email))

	if len(keystr) == 0 {
		derBytes, priv, err := h.cema.Generate(email)
		if err != nil {
			return nil, err
		}

		cert := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		certstr = pem.EncodeToMemory(cert)
		if err := h.cama.Set(fmt.Sprintf("connect.forfarmers.eu:%s:cert", email), cert); err != nil {
			return nil, err
		}

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
		keystr = pem.EncodeToMemory(key)
		if err := h.cama.Set(fmt.Sprintf("connect.forfarmers.eu:%s:key", email), key); err != nil {
			return nil, err
		}
	}

	// check certificate
	cs := &ConnectSession{
		email:   email,
		c:       h,
		certstr: certstr,
		keystr:  keystr,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

func (h *Proxy) Host(host string) string {
	log.Info("Mapping request %s", host)
	if v, ok := h.Mapping[host]; ok {
		log.Info("Mapping host %s to %s", host, v)
		return v
	}
	return host
}

func (h *Proxy) NewSession(email string) (http.RoundTripper, error) {
	cs := &ProxySession{
		c: h,
	}

	cs.RoundTripper = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                cs.DialTLS,
		DialTLS:             cs.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return cs, nil
}

var _ = backends.Register2("proxy", func() backends.Backend {
	return &Proxy{}
})

var _ = backends.Register2("client-certificate", func() backends.Backend {
	cema, err := NewCertificateManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	cama, err := NewCacheManager()
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return &Connect{
		cema: cema,
		cama: cama,
	}
})
