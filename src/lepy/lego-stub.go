package main

import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type LegoInputArgs struct {
	Email  string `json:"email"`
	Server string `json:"server"`
	CSR    string `json:"csr"`
	Plugin string `json:"plugin"`
	Env    map[string]interface{}
}

type LegoOutputResponse struct {
	CSR               string `json:"csr"`
	PrivateKey        string `json:"private_key"`
	Certificate       string `json:"certificate"`
	IssuerCertificate string `json:"issuer_certificate"`
	Metadata          `json:"metadata"`
}

type Metadata struct {
	StableURL string `json:"stable_url"`
	URL       string `json:"url"`
	Domain    string `json:"domain"`
}

type LetsEncryptUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LetsEncryptUser) GetEmail() string {
	return u.Email
}
func (u LetsEncryptUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

//export RunLegoCommand
func RunLegoCommand(message *C.char) *C.char {
	goStrMessage := C.GoString(message)
	var CLIArgs LegoInputArgs
	if err := json.Unmarshal([]byte(goStrMessage), &CLIArgs); err != nil {
		log.Fatal("cli args failed validation", err.Error())
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("couldn't generate priv key", err)
	}

	user := LetsEncryptUser{
		Email: CLIArgs.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(&user)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = fmt.Sprintf("https://%s/dir", CLIArgs.Server)
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal("couldn't create lego client: ", err)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "5002"))
	if err != nil {
		log.Fatal("couldn't set http01 provider server", err)
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	if err != nil {
		log.Fatal("couldn't set tlsalpn01 provider", err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal("couldn't register user", err)
	}
	user.Registration = reg

	// request := certificate.ObtainRequest{
	// 	Domains: []string{"localhost"},
	// 	Bundle:  true,
	// }
	block, _ := pem.Decode([]byte(CLIArgs.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatalf("Failed to decode PEM block containing certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate request: %v", err)
	}

	request := certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: true,
	}
	certificates, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		log.Fatal("coudn't obtain cert: ", err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL
	response_message := LegoOutputResponse{
		CSR:               string(certificates.CSR),
		PrivateKey:        string(certificates.PrivateKey),
		Certificate:       string(certificates.Certificate),
		IssuerCertificate: string(certificates.IssuerCertificate),
		Metadata: Metadata{
			StableURL: certificates.CertStableURL,
			URL:       certificates.CertURL,
			Domain:    certificates.Domain,
		},
	}

	response_json, err := json.Marshal(response_message)
	if err != nil {
		log.Fatal("coudn't build response message: ", err)
	}
	return_message_ptr := C.CString(string(response_json))
	return return_message_ptr
}

func main() {}
