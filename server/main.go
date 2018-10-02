package main

import (
	// "io/ioutil"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"crypto/x509"

	"golang.org/x/net/http2"
)

var (
	opts = x509.VerifyOptions{
	}
)

func handler(w http.ResponseWriter, req *http.Request) {
	log.Printf("handler() got %v certificates", len(req.TLS.PeerCertificates))
	fmt.Printf("handler()\n")
	fmt.Printf("Received certificates: %+v\n", req.TLS.PeerCertificates)

	for _, cert := range req.TLS.PeerCertificates {
		fmt.Printf("Cert --- \n")
		fmt.Printf("Issuer: %+v\n", cert.Issuer)
		fmt.Printf("Subject: %+v\n", cert.Subject)
		chains, err := cert.Verify(opts)
		fmt.Printf("Certificate Chain: %+v\n", chains)
		if err != nil {
			w.Write([]byte("no verification, no go!"))
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Received certificates: %v", req.TLS.PeerCertificates)))
}

func init(){
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	opts.Roots = certPool


	/*
	b, err := ioutil.ReadFile("assets/server.crt")
	if err != nil {
		panic(err)
	}
	serverCert, err := x509.ParseCertificate(b)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Cert: %+v\n", serverCert)
	*/
}

func main() {
	http.HandleFunc("/", handler)

	server := &http.Server{
		Addr:    ":8000",
		Handler: nil,
		TLSConfig: &tls.Config{
			ClientAuth:  	tls.RequireAnyClientCert,
			MinVersion:		tls.VersionTLS12,
		},
	}

	http2.ConfigureServer(server, nil)

	fmt.Println("Listening on https://localhost:8000")
	log.Fatal(server.ListenAndServeTLS("assets/server.crt", "assets/server.key"))
}
