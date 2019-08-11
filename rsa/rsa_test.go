package rsa

import (
	"bytes"
	"os"
	"testing"
)

func TestNewRSAKeyPairForJWT(t *testing.T) {
	var buf bytes.Buffer
	NewRSAKeyPairForJWT(&buf, false)
	if len(buf.String()) == 0 {
		t.Fatal("rsa buffer should not be empty")
	}
	NewRSAKeyPairForJWT(os.Stdout, true)
	NewRSAKeyPairForJWT(os.Stdout, false)
}
