package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/http2"
)

func handler(w http.ResponseWriter, req *http.Request) {
	log.Printf("handler() got %v certificates", len(req.TLS.PeerCertificates))
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
