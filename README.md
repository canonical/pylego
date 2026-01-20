# pylego

pylego is a python extension package to utilize the certificate management application [Lego](https://github.com/go-acme/lego) written in Golang in python.

## Installation

To install this package, all you need to do is run

```
pip install .
```

in your preferred Python venv.

## Usage

You can import the lego command and run any function that you can run from the CLI:

```python
from pylego import run_lego_command
test_env = {"NAMECHEAP_API_USER": "user", "NAMECHEAP_API_KEY": "key"}
run_lego_command(
    "something@gmail.com",
    "https://localhost/directory",
    b"-----BEGIN CERTIFICATE REQUEST----- ...",
    env=test_env,
    plugin="namecheap",
    private_key="-----BEGIN RSA PRIVATE KEY-----",
)
```

| Argument      | Description                                                                                                                                                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `email`       | The provided email will be registered to the ACME server. It may receive some emails notifying the user about certificate expiry.                                                                                                                        |
| `server`      | This is the full URL of a server that implements the ACME protocol. While letsencrypt is the most common one, there are other programs that provide this facility like Vault.                                                                            |
| `csr`         | This must be a PEM string in bytes that is user generated and valid as according to the ACME server that is being provided above. Many providers have different requirements for what is allowed to be in the fields of the CSR.                         |
| `plugin`      | Provider to use: `http` (HTTP-01), `tls` (TLS-ALPN-01), or any LEGO DNS provider from [here](https://go-acme.github.io/lego/dns/). If no plugin is provided, pylego uses HTTP-01 by default.                                                             |
| `env`         | The env is a dictionary mapping of strings to strings that will be loaded into the environment for LEGO to use. All plugins require some configuration values loaded into the environment. You can find them [here](https://go-acme.github.io/lego/dns/) |
| `private_key` | The provided private key will be used to register the user to the ACME server (not the key that signed the CSR), if not provided pylego will generate a new one                                                                                          |

On top of the environment variables that LEGO supports, we have some extra ones that we use to configure the library:

| Key               | Description                                                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `SSL_CERT_FILE`   | Path to a CA certificate file for pylego to trust. This can be used for trusting the certificate of the ACME server provided. |
| `HTTP01_IFACE`    | Interface for the HTTP-01 challenge (when no DNS plugin is used or when `plugin=http`). Any interface by default.             |
| `HTTP01_PORT`     | Port for the HTTP-01 challenge (when no DNS plugin is used or when `plugin=http`). 80 by default.                             |
| `TLSALPN01_IFACE` | Interface for the TLS-ALPN-01 challenge (when `plugin=tls`). Any interface by default.                                        |
| `TLSALPN01_PORT`  | Port for the TLS-ALPN-01 challenge (when `plugin=tls`). 443 by default.                                                       |

## Error Handling

pylego provides structured error handling through the `LEGOError` exception class. All errors raised by `run_lego_command()` include detailed information to help diagnose issues.

### LEGOError Attributes

When an error occurs, the `LEGOError` exception contains the following attributes:

```python
from pylego import run_lego_command, LEGOError, ErrorCode

try:
    result = run_lego_command(...)
except LEGOError as e:
    print(f"Error type: {e.type}")        # "acme" or "lego"
    print(f"Error code: {e.code}")        # Specific error code (see below)
    print(f"Detail: {e.detail}")          # Human-readable error message
    print(f"Status: {e.status}")          # HTTP status (ACME errors only)
    print(f"ACME type: {e.acme_type}")    # Full ACME URN (ACME errors only)
    print(f"Subproblems: {e.subproblems}") # List of subproblems (ACME errors)
    print(f"Raw info: {e.info}")          # Complete error dictionary
```

### Error Types

- **`acme`**: Errors returned by the ACME server (e.g., validation failures, rate limits)
- **`lego`**: Errors from the lego library or input validation (e.g., invalid CSR, DNS provider issues)

### Error Codes

pylego uses structured error codes to identify specific failure scenarios. Import `ErrorCode` for constant values:

```python
from pylego import ErrorCode

# Lego library error codes
ErrorCode.INVALID_ARGUMENTS              # Invalid input arguments
ErrorCode.INVALID_ENVIRONMENT            # Failed to set environment variables
ErrorCode.INVALID_PRIVATE_KEY            # Private key parsing failed
ErrorCode.KEY_GENERATION_FAILED          # Failed to generate new private key
ErrorCode.INVALID_CSR                    # CSR parsing or validation failed
ErrorCode.DNS_PROVIDER_FAILED            # DNS provider configuration failed
ErrorCode.LEGO_CLIENT_CREATION_FAILED    # Failed to create lego client
ErrorCode.ACCOUNT_REGISTRATION_FAILED    # ACME account registration failed
ErrorCode.CERTIFICATE_OBTAIN_FAILED      # Certificate issuance failed
ErrorCode.CERTIFICATE_REQUEST_FAILED     # General certificate request failure
ErrorCode.NETWORK_ERROR                  # Network connectivity issues
ErrorCode.MARSHALING_FAILED              # Internal JSON serialization error
```

### ACME Error Codes

For ACME errors (`e.type == "acme"`), the error code is extracted from the ACME problem type URN. Common ACME error codes include:

- `unauthorized` - Authorization failed for domain
- `dns` - DNS validation issues
- `rateLimited` - Rate limit exceeded
- `badCSR` - Invalid certificate signing request
- `caa` - CAA record prevents issuance
- `connection` - Server couldn't connect to validate

ACME errors also include the full URN in `e.acme_type` (e.g., `urn:ietf:params:acme:error:unauthorized`).

### Subproblems

ACME errors may include subproblems that provide detailed information about specific failures:

```python
from pylego import run_lego_command, LEGOError

try:
    result = run_lego_command(...)
except LEGOError as e:
    if e.type == "acme" and e.subproblems:
        for subproblem in e.subproblems:
            print(f"  Type: {subproblem.type}")
            print(f"  Detail: {subproblem.detail}")
            print(f"  Identifier: {subproblem.identifier.type}:{subproblem.identifier.value}")
```

### Error Handling Examples

**Example 1: Handle specific error codes**

```python
from pylego import run_lego_command, LEGOError, ErrorCode

try:
    result = run_lego_command(
        email="admin@example.com",
        server="https://acme-v02.api.letsencrypt.org/directory",
        csr=csr_bytes,
        env=env_vars,
    )
except LEGOError as e:
    if e.code == ErrorCode.INVALID_CSR:
        print("CSR validation failed. Please check your certificate request.")
    elif e.code == ErrorCode.DNS_PROVIDER_FAILED:
        print(f"DNS provider error: {e.detail}")
    elif e.code == ErrorCode.NETWORK_ERROR:
        print("Network connectivity issue. Please check your connection.")
    else:
        print(f"Certificate request failed: {e}")
```

**Example 2: Differentiate between ACME and lego errors**

```python
from pylego import run_lego_command, LEGOError

try:
    result = run_lego_command(...)
except LEGOError as e:
    if e.type == "acme":
        # ACME server rejected the request
        print(f"ACME server error [{e.code}]: {e.detail}")
        if e.status:
            print(f"HTTP Status: {e.status}")
        if e.subproblems:
            print("Validation failures:")
            for sub in e.subproblems:
                print(f"  - {sub.identifier.value}: {sub.detail}")
    else:
        # Configuration or library error
        print(f"Configuration error [{e.code}]: {e.detail}")
```

**Example 3: Logging complete error information**

```python
import json
from pylego import run_lego_command, LEGOError

try:
    result = run_lego_command(...)
except LEGOError as e:
    # Log complete error details for debugging
    error_log = {
        "type": e.type,
        "code": e.code,
        "detail": e.detail,
        "status": e.status,
        "acme_type": e.acme_type,
        "subproblems": [
            {
                "type": sub.type,
                "detail": sub.detail,
                "identifier": {"type": sub.identifier.type, "value": sub.identifier.value},
            }
            for sub in e.subproblems
        ],
    }
    print(json.dumps(error_log, indent=2))
```

## How does it work?

Golang supports building a shared c library from its CLI build tool. We import and use the LEGO application from GoLang, and provide a stub with C bindings so that the shared C binary we produce exposes a C API for other programs to import and utilize. pylego then uses the [ctypes](https://docs.python.org/3/library/ctypes.html) standard library in python to load this binary, and make calls to its methods.

The output binary, `lego.so`, is installed alongside pylego, and pylego exposes a python function called run_lego_command that will convert the arguments into a JSON message, and send it to LEGO.

On `pip install`, setuptools attempts to build this binary by running the command

```
go build -o lego.so -buildmode=c-shared lego.go
```

If we don't have a .whl that supports your environment, you will need to have Go installed and configured for Python to be able to build this binary.

## License

The `Lego` library used in this project is licensed under the [MIT License](https://github.com/go-acme/lego/blob/master/LICENSE).

`pylego` itself is licensed under the [Apache License, Version 2.0](./LICENSE).
