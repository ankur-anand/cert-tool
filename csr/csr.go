package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ankur-anand/go-pki-service/ca"
)

// Req Respresent a new CSR Request.
type Req struct {
	certTemplate *x509.Certificate
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
}

// GenerateNew generates a new CSR Req
func GenerateNew(cnName string) Req {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"GO_PKI_SERVICE"},
			Country:       []string{"IN"},
			Province:      []string{"KA"},
			Locality:      []string{"BLR"},
			StreetAddress: []string{"BLR-OLD"},
			CommonName:    cnName,
			PostalCode:    []string{"000000"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	return Req{
		certTemplate: cert,
		privateKey:   priv,
		publicKey:    pub,
	}
}

// CASignedCert returns all the ca signed certificate
type CASignedCert struct {
	SignedCertificate []byte
	PrivateKey        []byte
}

// SignCertificate sign the certificate with the passed ca.Authority
func (r Req) SignCertificate(authority ca.Authority) CASignedCert {
	caAuthorityCertificates, err := tls.X509KeyPair(authority.PublicSignedCertificate, authority.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	caAuth, err := x509.ParseCertificate(caAuthorityCertificates.Certificate[0])
	if err != nil {
		panic(err)
	}
	// Sign the certificate
	certSigned, err := x509.CreateCertificate(rand.Reader, r.certTemplate, caAuth, r.publicKey, caAuthorityCertificates.PrivateKey)
	if err != nil {
		panic(err)
	}

	publicSignedCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certSigned})
	if publicSignedCertificate == nil {
		log.Println("cauthSigned has invalid headers and cannot be encoded")
		return CASignedCert{}
	}
	fmt.Println("********************** envoy.ankuranand.in.pem ******************")
	fmt.Println(string(publicSignedCertificate))
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r.privateKey)})
	if privateKey == nil {
		log.Println("privateKey for CA Authority has invalid headers and cannot be encoded")
		return CASignedCert{}
	}
	fmt.Println("********************** private.key ***********************************")
	fmt.Println(string(privateKey))
	return CASignedCert{SignedCertificate: certSigned, PrivateKey: privateKey}
}
