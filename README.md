## cert-tool

A command line tool collection to generate different keypair and certificate
 for testing purpose in pure go.
 
 Installation
 
 `go get -u github.com/ankur-anand/cert-tool`
 
 ### JWT RSA Key pair
 
 **Public Key is DER-encoded PKIX format.**
 
 ```bash
  cert-tool -type rsa -for jwt
 ```
 If public and private key needs to be base64 encoded
 ```bash
 cert-tool -type rsa -for jwt -base64 true
```
