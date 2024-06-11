# lepy

lepy is a python extension package to utilize the certificate management application [Lego](https://github.com/go-acme/lego) written in Golang in python.

## Installation
To install this package, all you need to do is run
```
pip install .
```
in your preferred Python venv.

You can then import the lego command and run any function that you can run from the CLI:
```
from lepy import run_lego_command
test_env = {"NAMECHEAP_API_USER": "user", "NAMECHEAP_API_KEY": "key"}
run_lego_command("something@gmail.com", "127.0.0.1", "/path/to/csr.pem", "namecheap", test_env)
```

## How does it work?

Golang supports building a shared c library from its CLI build tool. We import and use the LEGO application from GoLang, and provide a stub with C bindings so that the shared C binary we produce exposes a C API for other programs to import and utilize. Lepy then uses the [ctypes](https://docs.python.org/3/library/ctypes.html) standard library in python to load this binary, and make calls to its methods.

The output binary, `lego.so`, is installed alongside lepy, and lepy exposes a python function called run_lego_command that will convert the arguments into a JSON message, and send it to LEGO.

On `pip install`, setuptools attempts to build this binary by running the command
```
go build -o lego.so -buildmode=c-shared lego-stub.go
```
If we don't have a .whl that supports your environment, you will need to have Go installed and configured for Python to be able to build this binary.