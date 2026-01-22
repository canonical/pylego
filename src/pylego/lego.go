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
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// Error code constants
const (
	ErrInvalidArguments          = "invalid_arguments"
	ErrInvalidEnvironment        = "invalid_environment"
	ErrCertificateRequestFailed  = "certificate_request_failed"
	ErrInvalidPrivateKey         = "invalid_private_key"
	ErrKeyGenerationFailed       = "key_generation_failed"
	ErrLegoClientCreationFailed  = "lego_client_creation_failed"
	ErrDNSProviderFailed         = "dns_provider_failed"
	ErrAccountRegistrationFailed = "account_registration_failed"
	ErrInvalidCSR                = "invalid_csr"
	ErrCertificateObtainFailed   = "certificate_obtain_failed"
	ErrNetworkError              = "network_error"
	ErrMarshalingFailed          = "marshaling_failed"
)

type LegoInputArgs struct {
	Email              string `json:"email"`
	PrivateKey         string `json:"private_key,omitempty"`
	Server             string `json:"server"`
	CSR                string `json:"csr"`
	Plugin             string `json:"plugin"`
	Env                map[string]string
	DNSPropagationWait int      `json:"dns_propagation_wait,omitempty"`
	DNSNameservers     []string `json:"dns_nameservers,omitempty"`
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

type Subproblem struct {
	Type       string     `json:"type"`                 // Error type URN
	Detail     string     `json:"detail"`               // Human-readable message
	Identifier Identifier `json:"identifier,omitempty"` // The identifier that caused this subproblem
}

type Identifier struct {
	Type  string `json:"type"`  // "dns" or "ip"
	Value string `json:"value"` // Domain name or IP address
}

type ErrorResponse struct {
	Type        string       `json:"type"`                  // "acme" for CA server errors, "lego" for everything else
	Code        string       `json:"code"`                  // Error code or category
	Status      *int         `json:"status,omitempty"`      // HTTP status if applicable (ACME errors)
	Detail      string       `json:"detail"`                // Human-readable message
	ACMEType    string       `json:"acme_type,omitempty"`   // Full ACME URN if applicable
	Subproblems []Subproblem `json:"subproblems,omitempty"` // Detailed subproblems from ACME errors
}

type LegoResponse struct {
	Success bool                `json:"success"`
	Error   *ErrorResponse      `json:"error,omitempty"`
	Data    *LegoOutputResponse `json:"data,omitempty"`
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var (
		netErr net.Error
		dnsErr *net.DNSError
		opErr  *net.OpError
	)

	switch {
	case errors.As(err, &netErr):
		return true
	case errors.As(err, &dnsErr):
		return true
	case errors.As(err, &opErr):
		return true
	default:
		return false
	}
}

func extractSubproblems(problemDetails *acme.ProblemDetails) []Subproblem {
	var subproblems []Subproblem
	for _, sub := range problemDetails.SubProblems {
		subCode := "unknown"
		if sub.Type != "" {
			parts := strings.Split(sub.Type, ":")
			if len(parts) > 0 {
				subCode = parts[len(parts)-1]
			}
		}
		subproblems = append(subproblems, Subproblem{
			Type:   subCode,
			Detail: sub.Detail,
			Identifier: Identifier{
				Type:  sub.Identifier.Type,
				Value: sub.Identifier.Value,
			},
		})
	}
	return subproblems
}

func wrapError(err error, context string) *ErrorResponse {
	if err == nil {
		return nil
	}

	var ctxErr *contextError
	if errors.As(err, &ctxErr) {
		context = ctxErr.context
		err = ctxErr.original
	}

	var problemDetails *acme.ProblemDetails
	if errors.As(err, &problemDetails) {
		code := "unknown"
		if problemDetails.Type != "" {
			parts := strings.Split(problemDetails.Type, ":")
			if len(parts) > 0 {
				code = parts[len(parts)-1]
			}
		}
		status := problemDetails.HTTPStatus

		return &ErrorResponse{
			Type:        "acme",
			Code:        code,
			Status:      &status,
			Detail:      problemDetails.Detail,
			ACMEType:    problemDetails.Type,
			Subproblems: extractSubproblems(problemDetails),
		}
	}

	if isNetworkError(err) {
		return &ErrorResponse{
			Type:   "lego",
			Code:   ErrNetworkError,
			Detail: err.Error(),
		}
	}

	return &ErrorResponse{
		Type:   "lego",
		Code:   context,
		Detail: err.Error(),
	}
}

func buildErrorResponse(err error, context string) *C.char {
	response := LegoResponse{
		Success: false,
		Error:   wrapError(err, context),
	}
	responseJSON, marshalErr := json.Marshal(response)
	if marshalErr == nil {
		return C.CString(string(responseJSON))
	}

	fallbackResponse := LegoResponse{
		Success: false,
		Error: &ErrorResponse{
			Type:   "lego",
			Code:   ErrMarshalingFailed,
			Detail: marshalErr.Error(),
		},
	}
	fallbackJSON, _ := json.Marshal(fallbackResponse)

	return C.CString(string(fallbackJSON))
}

func buildSuccessResponse(data *LegoOutputResponse) *C.char {
	response := LegoResponse{
		Success: true,
		Data:    data,
	}
	responseJSON, marshalErr := json.Marshal(response)
	if marshalErr == nil {
		return C.CString(string(responseJSON))
	}

	fallbackResponse := LegoResponse{
		Success: false,
		Error: &ErrorResponse{
			Type:   "lego",
			Code:   ErrMarshalingFailed,
			Detail: marshalErr.Error(),
		},
	}
	fallbackJSON, _ := json.Marshal(fallbackResponse)

	return C.CString(string(fallbackJSON))
}

type contextError struct {
	original error
	context  string
}

func (e *contextError) Error() string {
	return e.original.Error()
}

func (e *contextError) Unwrap() error {
	return e.original
}

func wrapWithContext(err error, context string) error {
	return &contextError{original: err, context: context}
}

//export RunLegoCommand
func RunLegoCommand(message *C.char) *C.char {
	CLIArgs, err := extractArguments(C.GoString(message))
	if err != nil {
		return buildErrorResponse(err, ErrInvalidArguments)
	}
	for k, v := range CLIArgs.Env {
		if err := os.Setenv(k, v); err != nil {
			return buildErrorResponse(err, ErrInvalidEnvironment)
		}

	}
	certificate, err := requestCertificate(CLIArgs.Email, CLIArgs.PrivateKey, CLIArgs.Server, CLIArgs.CSR, CLIArgs.Plugin, CLIArgs.DNSPropagationWait, CLIArgs.DNSNameservers)
	if err != nil {
		return buildErrorResponse(err, ErrCertificateRequestFailed)
	}
	return buildSuccessResponse(certificate)
}

func requestCertificate(email, privateKeyPem, server, csr, plugin string, propagationWait int, nameservers []string) (*LegoOutputResponse, error) {
	var privateKey crypto.PrivateKey
	if privateKeyPem != "" {
		parsedKey, err := certcrypto.ParsePEMPrivateKey([]byte(privateKeyPem))
		if err != nil {
			return nil, wrapWithContext(err, ErrInvalidPrivateKey)
		}
		privateKey = parsedKey
	} else {
		generatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, wrapWithContext(err, ErrKeyGenerationFailed)
		}
		privateKey = generatedKey
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
		return nil, wrapWithContext(err, ErrLegoClientCreationFailed)
	}

	err = configureClientChallenges(client, plugin, propagationWait, nameservers)
	if err != nil {
		return nil, wrapWithContext(err, ErrDNSProviderFailed)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, wrapWithContext(err, ErrAccountRegistrationFailed)
	}
	user.Registration = reg

	block, _ := pem.Decode([]byte(csr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, wrapWithContext(errors.New("failed to decode PEM block"), ErrInvalidCSR)
	}
	csrObject, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, wrapWithContext(err, ErrInvalidCSR)
	}
	request := certificate.ObtainForCSRRequest{
		CSR:    csrObject,
		Bundle: true,
	}
	certificates, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		return nil, wrapWithContext(err, ErrCertificateObtainFailed)
	}

	return &LegoOutputResponse{
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

func configureClientChallenges(client *lego.Client, plugin string, propagationWait int, nameservers []string) error {
	switch plugin {
	case "", "http":
		if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer(os.Getenv("HTTP01_IFACE"), os.Getenv("HTTP01_PORT"))); err != nil {
			return errors.Join(errors.New("couldn't set http01 provider server: "), err)
		}
		return nil
	case "tls":
		if err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(os.Getenv("TLSALPN01_IFACE"), os.Getenv("TLSALPN01_PORT"))); err != nil {
			return errors.Join(errors.New("couldn't set tlsalpn01 provider server: "), err)
		}
		return nil
	default:
		dnsProvider, err := dns.NewDNSChallengeProviderByName(plugin)
		if err != nil {
			return errors.Join(fmt.Errorf("couldn't create %s provider: ", plugin), err)
		}
		var wait time.Duration
		if propagationWait > 0 {
			wait = time.Duration(propagationWait) * time.Second
		}

		err = client.Challenge.SetDNS01Provider(dnsProvider,
			dns01.CondOption(os.Getenv("DNS_PROPAGATION_DISABLE_ANS") != "",
				dns01.DisableAuthoritativeNssPropagationRequirement()),
			dns01.CondOption(wait > 0,
				dns01.PropagationWait(wait, true)),
			dns01.CondOption(os.Getenv("DNS_PROPAGATION_RNS") != "", dns01.RecursiveNSsPropagationRequirement()),
			dns01.CondOption(len(nameservers) > 0,
				dns01.AddRecursiveNameservers(nameservers)))
		if err != nil {
			return errors.Join(fmt.Errorf("couldn't set %s DNS provider server: ", plugin), err)
		}
		return nil
	}
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

func extractArguments(jsonMessage string) (LegoInputArgs, error) {
	var CLIArgs LegoInputArgs
	if err := json.Unmarshal([]byte(jsonMessage), &CLIArgs); err != nil {
		return CLIArgs, errors.Join(errors.New("cli args failed validation: "), err)
	}
	return CLIArgs, nil
}

func main() {}
