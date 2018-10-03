package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

func jsTestHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")

	p12Bytes, err := ioutil.ReadFile("assets/index.js")
	if err != nil {
		log.Fatal(err)
		return
	}

	w.Header().Set("Connection", "close")

	w.Write(p12Bytes)

	log.Printf("sent javascript")
}

func namePlsHandler(w http.ResponseWriter, req *http.Request) {
	certs, err := verifyCertificate(req.TLS.PeerCertificates)
	if err != nil {
		w.Write([]byte("invalid certificate"))
		return
	}

	b, err := json.Marshal(&struct {
		ClientName []string `json:"clientname"`
	}{
		ClientName: certs,
	})

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(b)
}

func htmlTestHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	p12Bytes, err := ioutil.ReadFile("assets/index.html")
	if err != nil {
		log.Fatal(err)
		return
	}

	w.Write(p12Bytes)

	log.Printf("sent index.html")
}

func verifyCertificate(certs []*x509.Certificate) ([]string, error) {
	if len(certs) == 0 {
		return []string{}, fmt.Errorf("no certificates")
	}

	cnChain := []string{}
	for _, cert := range certs {
		cnChain = append(cnChain, string(cert.Subject.CommonName))
	}
	log.Printf("loginHandler() got certificate chain: %v", strings.Join(cnChain, ","))

	var authenticatedChain [][]*x509.Certificate
	for _, cert := range certs {
		validChain, err := cert.Verify(x509.VerifyOptions{
			Roots:                     certPool,
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
		return []string{}, fmt.Errorf("no valid chains found in certificate")
	}

	return cnChain, nil
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	// Request the HTTP client to close this connection, as keeping the connection open provides
	// a strange UX where the client is not requested to chose a certificate
	w.Header().Set("Connection", "close")

	if len(req.TLS.PeerCertificates) == 0 {
		w.Write([]byte("no certificate supplied!\n"))
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
			Roots:                     certPool,
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
	w.Write([]byte(fmt.Sprintf("Welcome: %s\n", cnChain[0])))

}

var certPool *x509.CertPool

func init() {
	certPool = x509.NewCertPool()
	b, err := ioutil.ReadFile("assets/ca.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(b)
}

func main() {
	authMux := http.NewServeMux()
	authMux.HandleFunc("/", loginHandler)
	authMux.HandleFunc("/me", namePlsHandler)
	authMux.HandleFunc("/static/index.js", jsTestHandler)
	authServer := &http.Server{
		Addr:    ":8000",
		Handler: authMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}
	http2.ConfigureServer(authServer, nil)

	registerMux := http.NewServeMux()
	registerMux.HandleFunc("/register", registerHandler)
	registerMux.HandleFunc("/static/index.js", jsTestHandler)
	registerMux.HandleFunc("/", htmlTestHandler)
	registerServer := &http.Server{
		Addr:    ":9000",
		Handler: registerMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.NoClientCert,
			MinVersion: tls.VersionTLS12,
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
