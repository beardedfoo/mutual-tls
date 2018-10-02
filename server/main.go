package main

import (
	"io/ioutil"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"crypto/x509"
	"strings"

	"golang.org/x/net/http2"
)

var (
	opts = x509.VerifyOptions{
	}
)

func handler(w http.ResponseWriter, req *http.Request) {
	log.Printf("handler() got %v certificates", len(req.TLS.PeerCertificates))

	// Request the HTTP client to close this connection, as keeping the connection open provides
	// a strange UX where the client is not requested to chose a certificate
	w.Header().Set("Connection", "close")

	cnChain := []string{}
	for _, cert := range req.TLS.PeerCertificates {
		cnChain = append(cnChain, string(cert.Subject.CommonName))
		chains, err := cert.Verify(opts)
		fmt.Printf("Certificate Chain: %+v\n", chains)
		if err != nil {
			w.Write([]byte("no verification, no go!"))
			return
		}
	}

	log.Printf("handler() got %v certificates", strings.Join(cnChain, ","))


	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Received certificates: %v", req.TLS.PeerCertificates)))
}

func init(){
	certPool := x509.NewCertPool()

	b, err := ioutil.ReadFile("assets/server.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(b)

	opts.Roots = certPool

	fmt.Printf("opts: %+v\n", opts)
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
