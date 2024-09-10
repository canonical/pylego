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
	"errors"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

type RequestCertificateInputArgs struct {
	Email  string `json:"email"`
	Server string `json:"server"`
	CSR    string `json:"csr"`
	Plugin string `json:"plugin"`
	Env    map[string]string
}

type RequestCertificateOutputResponse struct {
	CSR               string `json:"csr"`
	PrivateKey        string `json:"private_key"`
	Certificate       string `json:"certificate"`
	IssuerCertificate string `json:"issuer_certificate"`
	Metadata          `json:"metadata"`
}

type ValidateDNSProviderInputArgs struct {
	PluginName    string            `json:"plugin_name"`
	PluginOptions map[string]string `json:"plugin_options"`
}

type Metadata struct {
	StableURL string `json:"stable_url"`
	URL       string `json:"url"`
	Domain    string `json:"domain"`
}

//export RequestCertificate
func RequestCertificate(message *C.char) *C.char {
	args, err := extractRequestCertificateArguments(C.GoString(message))
	if err != nil {
		return C.CString(fmt.Sprint("error: couldn't extract arguments: ", err))
	}
	for k, v := range args.Env {
		if err := os.Setenv(k, v); err != nil {
			return C.CString(fmt.Sprint("error: couldn't load environment variables: ", err))
		}

	}
	certificate, err := requestCertificate(args.Email, args.Server, args.CSR, args.Plugin)
	if err != nil {
		return C.CString(fmt.Sprint("error: couldn't request certificate: ", err))
	}
	response_json, err := json.Marshal(certificate)
	if err != nil {
		return C.CString(fmt.Sprint("error: coudn't build response message: ", err))
	}
	return_message_ptr := C.CString(string(response_json))
	return return_message_ptr
}

//export ValidateDNSProvider
func ValidateDNSProvider(message *C.char) *C.char {
	args, err := extractValidateDNSPluginArguments(C.GoString(message))
	if err != nil {
		return C.CString(fmt.Sprint("error: couldn't extract arguments: ", err))
	}
	for k, v := range args.PluginOptions {
		if err := os.Setenv(k, v); err != nil {
			return C.CString(fmt.Sprint("error: couldn't load environment variables: ", err))
		}
	}
	_, err = dns.NewDNSChallengeProviderByName(args.PluginName)
	if err != nil {
		return C.CString(fmt.Sprint("error: couldn't validate provider: ", err))
	}
	return_message_ptr := C.CString(string(""))
	return return_message_ptr
}

func requestCertificate(email, server, csr, plugin string) (*RequestCertificateOutputResponse, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate priv key: %s", err)
	}
	user := LetsEncryptUser{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(&user)

	config.CADirURL = server
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("couldn't create lego client: %s", err)
	}

	err = configureClientChallenges(client, plugin)
	if err != nil {
		return nil, fmt.Errorf("couldn't configure client challenges: %s", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("couldn't register user: %s", err)
	}
	user.Registration = reg

	block, _ := pem.Decode([]byte(csr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("failed to decode PEM block containing certificate request")
	}
	csrObject, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %s", err)
	}
	request := certificate.ObtainForCSRRequest{
		CSR:    csrObject,
		Bundle: true,
	}
	certificates, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		return nil, fmt.Errorf("coudn't obtain cert: %s", err)
	}

	return &RequestCertificateOutputResponse{
		CSR:               string(certificates.CSR),
		PrivateKey:        string(certificates.PrivateKey),
		Certificate:       string(certificates.Certificate),
		IssuerCertificate: string(certificates.IssuerCertificate),
		Metadata: Metadata{
			StableURL: certificates.CertStableURL,
			URL:       certificates.CertURL,
			Domain:    certificates.Domain,
		},
	}, nil
}

func configureClientChallenges(client *lego.Client, plugin string) error {
	switch plugin {
	case "":
		err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer(os.Getenv("HTTP01_IFACE"), os.Getenv("HTTP01_PORT")))
		if err != nil {
			return errors.Join(errors.New("couldn't set http01 provider server: "), err)
		}
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(os.Getenv("TLSALPN01_IFACE"), os.Getenv("TLSALPN01_PORT")))
		if err != nil {
			return errors.Join(errors.New("couldn't set tlsalpn01 provider server: "), err)
		}
	default:
		dnsProvider, err := dns.NewDNSChallengeProviderByName(plugin)
		if err != nil {
			return errors.Join(fmt.Errorf("couldn't create %s provider: ", plugin), err)
		}
		err = client.Challenge.SetDNS01Provider(dnsProvider)
		if err != nil {
			return errors.Join(fmt.Errorf("couldn't set %s DNS provider server: ", plugin), err)
		}
	}
	return nil
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

func extractRequestCertificateArguments(jsonMessage string) (RequestCertificateInputArgs, error) {
	var args RequestCertificateInputArgs
	if err := json.Unmarshal([]byte(jsonMessage), &args); err != nil {
		return args, errors.Join(errors.New("request args failed validation: "), err)
	}
	return args, nil
}

func extractValidateDNSPluginArguments(jsonMessage string) (ValidateDNSProviderInputArgs, error) {
	var args ValidateDNSProviderInputArgs
	if err := json.Unmarshal([]byte(jsonMessage), &args); err != nil {
		return args, errors.Join(errors.New("request args failed validation: "), err)
	}
	return args, nil
}

func main() {}
