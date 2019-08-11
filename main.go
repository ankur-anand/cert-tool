package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ankur-anand/go-pki-service/rsa"
)

func usage() {
	usageStr := `Usage
	cert-tool -type [rsa] -for [jwt] -base64 [true|false]
	`

	fmt.Println(usageStr)
}

// list of arguments to support
type args struct {
	forUsage *string
	typeKey  *string
	b64      *bool
}

func main() {
	args := args{
		forUsage: flag.String("for", "", "The Usage of certificates"),
		typeKey:  flag.String("type", "", "algorithm to use"),
		b64:      flag.Bool("base64", false, "should output be base64 encoded"),
	}

	flag.Parse()
	if *args.forUsage == "" || *args.typeKey == "" {
		usage()
		return
	}
	// usage for jwt type
	if *args.forUsage == "jwt" {
		if *args.typeKey == "rsa" {
			rsa.NewRSAKeyPairForJWT(os.Stdout, *args.b64)
			return
		}
	}

	fmt.Println("Unknown operation currently")
	usage()
}
