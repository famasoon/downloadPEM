package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"
)

func showUsage() {
	fmt.Printf("%s -domain <domain>", os.Args[0])
	os.Exit(0)
}

func main() {
	if len(os.Args) < 3 {
		showUsage()
	}
	err := run(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
}

func enumDNS(cert *x509.Certificate) {
	for _, record := range cert.DNSNames {
		fmt.Printf("%s\n", record)
	}
}

func showCertInfo(cert *x509.Certificate) {
	inJPTime := cert.NotAfter.In(time.FixedZone("Asia/Tokyo", 9*60*60))
	fmt.Printf("CertVersion: %d\n", cert.Version)
	fmt.Printf("Cert Deadline: %s\n", inJPTime.Format("2006/01/02 15:04"))
	fmt.Println("Enumerate related DNS records in Certificate:")
	enumDNS(cert)
}

func run(url string) error {
	cert, err := getCertificatesPEM(url)
	if err != nil {
		return err
	}

	showCertInfo(cert)

	return nil
}

func getCertificatesPEM(url string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", url+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}
