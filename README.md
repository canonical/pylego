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
run_lego_command("something@gmail.com", "https://localhost/directory", "-----BEGIN CERTIFICATE REQUEST----- ...", "namecheap", test_env, "-----BEGIN RSA PRIVATE KEY-----")
```

| Argument | Description                                                                                                                                                                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `email`  | The provided email will be registered to the ACME server. It may receive some emails notifying the user about certificate expiry.                                                                                                                                |
| `server` | This is the full URL of a server that implements the ACME protocol. While letsencrypt is the most common one, there are other programs that provide this facility like Vault.                                                                                |
| `csr`    | This must be a PEM string in bytes that is user generated and valid as according to the ACME server that is being provided above. Many providers have different requirements for what is allowed to be in the fields of the CSR.                             |
| `plugin` | The plugin is a string that's supported by LEGO. The full list is located [here](https://go-acme.github.io/lego/dns/). On top of the LEGO provided ones, we have an extra plugin called `http` that will allow users to use HTTP01 and TLSALPN01 challenges. |
| `env`    | The env is a dictionary mapping of strings to strings that will be loaded into the environment for LEGO to use. All plugins require some configuration values loaded into the environment. You can find them [here](https://go-acme.github.io/lego/dns/)     |
| `private_key`    | The provided private key will be used to register the user to the ACME server (not the key that signed the CSR), if not provided pylego will generate a new one  |

On top of the environment variables that LEGO supports, we have some extra ones that we use to configure the library:

| Key               | Description                                                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `SSL_CERT_FILE`   | Path to a CA certificate file for pylego to trust. This can be used for trusting the certificate of the ACME server provided. |
| `HTTP01_IFACE`    | The interface to be used for the HTTP01 challenge if the plugin is chosen. Any interface by default.                          |
| `HTTP01_PORT`     | The port to be used for the HTTP01 challenge if the plugin is chosen. 80 by default.                                          |
| `TLSALPN01_IFACE` | The interface to be used for the TLSALPN01 challenge if the plugin is chosen. Any interface by default.                       |
| `TLSALPN01_PORT`  | The port to be used for the TLSALPN01 challenge if the plugin is chosen. 443 by default.                                      |

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
