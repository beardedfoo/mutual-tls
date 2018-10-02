package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
)

func handler(w http.ResponseWriter, req *http.Request) {
	// Request the HTTP client to close this connection, as keeping the connection open provides
	// a strange UX where the client is not requested to chose a certificate
	w.Header().Set("Connection", "close")

	cnChain := []string{}
	for _, cert := range req.TLS.PeerCertificates {
		cnChain = append(cnChain, string(cert.Subject.CommonName))
	}

	log.Printf("handler() got %v certificates", strings.Join(cnChain, ","))


	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Received certificates: %v", req.TLS.PeerCertificates)))
}

func main() {
	http.HandleFunc("/", handler)

	server := &http.Server{
		Addr:    ":8000",
		Handler: nil,
		TLSConfig: &tls.Config{
			ClientAuth:		tls.RequireAndVerifyClientCert,
			MinVersion:		tls.VersionTLS12,
		},
	}

	http2.ConfigureServer(server, nil)

	fmt.Println("Listening on https://localhost:8000")
	log.Fatal(server.ListenAndServeTLS("assets/server.crt", "assets/server.key"))
}
