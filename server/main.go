package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
)

func handler(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("handler()")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Received certificates: %v", req.TLS.PeerCertificates)))
}

func main() {
	http.HandleFunc("/", handler)

	server := &http.Server{
		Addr:    ":8000",
		Handler: nil,
	}

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates:	[]tls.Certificate{cert},
		ClientAuth:  	tls.VerifyClientCertIfGiven,
		MinVersion:		tls.VersionTLS12,
		NextProtos:  	[]string{"http/2"},
	}

	conn, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Listening on https://localhost:8000")
	tlsListener := tls.NewListener(conn, tlsConfig)
	server.Serve(tlsListener)
}
