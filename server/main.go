package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
)

func registerHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/x-pkcs12")

	p12Bytes, err := ioutil.ReadFile("assets/client.p12")
	if err != nil {
		log.Fatal(err)
		return
	}

	w.Write(p12Bytes)
	
	log.Printf("sent p12")
}


func loginHandler(w http.ResponseWriter, req *http.Request) {
	// Request the HTTP client to close this connection, as keeping the connection open provides
	// a strange UX where the client is not requested to chose a certificate
	w.Header().Set("Connection", "close")

	if len(req.TLS.PeerCertificates) == 0 {
		w.Write([]byte("no certificate supplied!"))
		return
	}

	w.Write([]byte(fmt.Sprintf("Received certificates: %v\n", req.TLS.PeerCertificates)))

	cnChain := []string{}
	for _, cert := range req.TLS.PeerCertificates {
		cnChain = append(cnChain, string(cert.Subject.CommonName))
	}
	log.Printf("loginHandler() got certificate chain: %v", strings.Join(cnChain, ","))


	var authenticatedChain [][]*x509.Certificate
	for _, cert := range req.TLS.PeerCertificates {
		validChain, err := cert.Verify(x509.VerifyOptions{
			Roots: certPool,
			MaxConstraintComparisions: 10,
		})
		if err == nil {
			fmt.Printf("Validated Certificate Chain: %+v\n", validChain)
			authenticatedChain = validChain
			break
		}
	}


	// If no chains validated, there is no login - write an error msg and return
	if authenticatedChain == nil {
		w.Write([]byte("no valid chains found in certificate!\n"))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("Welcome: %s", cnChain[0])))

}

var certPool *x509.CertPool

func init() {
	certPool := x509.NewCertPool()
	b, err := ioutil.ReadFile("assets/ca.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(b)
}

func main() {
	authMux := http.NewServeMux()
	authMux.HandleFunc("/", loginHandler)
	authServer := &http.Server{
		Addr:    ":8000",
		Handler: authMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}
	http2.ConfigureServer(authServer, nil)

	registerMux := http.NewServeMux()
	registerMux.HandleFunc("/", registerHandler)
	registerServer := &http.Server{
		Addr:	":9000",
		Handler: registerMux,
		TLSConfig: &tls.Config{
			ClientAuth:  	tls.NoClientCert,
			MinVersion:		tls.VersionTLS12,
		},
	}
	http2.ConfigureServer(registerServer, nil)

	fmt.Println("Listening on https://localhost:8000")
	go func() {
		log.Fatal(authServer.ListenAndServeTLS("assets/server.crt", "assets/server.key"))
	}()

	fmt.Println("Listening on https://localhost:9000")
	log.Fatal(registerServer.ListenAndServeTLS("assets/server.crt", "assets/server.key"))
}
