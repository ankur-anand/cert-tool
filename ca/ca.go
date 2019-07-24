package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"
)

// Authority represent an Ca Authority
type Authority struct {
	PublicSignedCertificate []byte
	PrivateKey              []byte
}

// GenerateNewCA Generates an public and private key for Certificate Authority.
// Right now most of the value are hardcoded.
func GenerateNewCA() (Authority, error) {
	cauth := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"GO_PKI_SERVICE"},
			Country:       []string{"IN"},
			Province:      []string{"KA"},
			Locality:      []string{"BLR"},
			StreetAddress: []string{"BLR-OLD"},
			PostalCode:    []string{"000000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	// generate a self signed certifcate
	cauthSigned, err := x509.CreateCertificate(rand.Reader, cauth, cauth, pub, priv)
	if err != nil {
		log.Println("creation of certificate authority failed", err)
		return Authority{}, err
	}

	// save the private and public signed key to memory
	publicSignedCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cauthSigned})
	if publicSignedCertificate == nil {
		log.Println("cauthSigned has invalid headers and cannot be encoded")
		return Authority{}, fmt.Errorf("cauthSigned has invalid headers and cannot be encoded")
	}

	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if privateKey == nil {
		log.Println("privateKey for CA Authority has invalid headers and cannot be encoded")
		return Authority{}, fmt.Errorf("privateKey for CA Authority has invalid headers and cannot be encoded")
	}
	return Authority{PublicSignedCertificate: publicSignedCertificate, PrivateKey: privateKey}, nil
}
