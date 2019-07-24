package ca

import (
	"testing"
)

func TestGenerateNewCA(t *testing.T) {
	authority, err := GenerateNewCA()
	if err != nil {
		t.Fatal(err)
	}

	if  len(authority.PublicSignedCertificate) == 0 || len(authority.PrivateKey) == 0 {
		t.Fatal("Length of the Public Certificate and Private Key should be not be Zero")
	}
}