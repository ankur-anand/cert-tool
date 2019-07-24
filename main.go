package main

import (
	"github.com/ankur-anand/go-pki-service/ca"
	"github.com/ankur-anand/go-pki-service/csr"
)

func main() {
	cAuth, _ := ca.GenerateNewCA()
	csr := csr.GenerateNew("envoy.ankuranand.in")
	_ = csr.SignCertificate(cAuth)
	// fmt.Println("********************** ca.pem ***********************************")
	// fmt.Println(string(cAuth.PublicSignedCertificate))
	// fmt.Println("***********************************************************")
	// fmt.Println("********************** envoy.ankuranand.in.pem ******************")
	// fmt.Println(string(signedCert.SignedCertificate))
	// fmt.Println("***********************************************************")
	// fmt.Println("********************** private.key ***********************************")
	// fmt.Println(string(signedCert.PrivateKey))
	// fmt.Println("***********************************************************")
}
