package main

import (
	"fmt"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
)

func certPEM() []byte {
	b, err := ioutil.ReadFile("assets/client.crt")
	if err != nil {
		panic(err)
	}
	return b
}

func rootPEM() []byte {
	b, err := ioutil.ReadFile("assets/ca.crt")
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	// Verifying with a custom list of root certificates.

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM()))
	if !ok {
		panic("failed to parse root certificate")
	}

	block, _ := pem.Decode([]byte(certPEM()))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		// DNSName: "beardedfoo",
		Roots:   roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	fmt.Printf("verified chains: %+v\n", chains)
}
