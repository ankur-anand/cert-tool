package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
)

type outPut struct {
	Base64     bool   `json:"base64"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// PrettyPrint Prints the data with Indentation
// it will output the result to the passed io.writer
func (o *outPut) prettyPrint(w io.Writer) {
	json, err := json.MarshalIndent(o, "", "\t")
	if err != nil {
		fmt.Printf("Indentation Print Failed with error %s", err)
	}
	w.Write(json)
}

// NewRSAKeyPairForJWT generate private and public key for
// JWT Verification and Testing Purposes.
// Default Key of Size 2048 is used
func NewRSAKeyPairForJWT(writer io.Writer, b64 bool) {
	// https://tools.ietf.org/html/rfc7518#section-3.3
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 2048)
	checkError(err)

	printKey(key, writer, b64)
}

func NewRSAKeyPair(bitSize int, writer io.Writer, b64 bool) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)
	printKey(key, writer, b64)
}

func printKey(key *rsa.PrivateKey, writer io.Writer, b64 bool) {
	publicKey := key.PublicKey
	// https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/
	priv := exportPrivateKey(key)
	pub := exportPublicPEMKey(&publicKey)
	// if the need is it to be base64 encoded

	if b64 {
		o := &outPut{
			Base64:     b64,
			PrivateKey: base64.StdEncoding.EncodeToString(priv),
			PublicKey:  base64.StdEncoding.EncodeToString(pub),
		}
		o.prettyPrint(writer)
		return
	}

	// else don't encode it to json.
	// /n character issue
	writer.Write([]byte("\n \n"))
	writer.Write(priv)
	writer.Write([]byte("\n \n"))
	writer.Write(pub)
}

func exportPrivateKey(key *rsa.PrivateKey) []byte {
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	encodedByte := pem.EncodeToMemory(privateKey)
	return encodedByte
}

func exportPublicPEMKey(pubkey *rsa.PublicKey) []byte {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	encodedByte := pem.EncodeToMemory(pemkey)
	return encodedByte
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
