"""Python interface that wraps the lego application CLI."""

import ctypes
import json
from dataclasses import dataclass
from pathlib import Path

here = Path(__file__).absolute().parent
so_file = here / ("lego.so")
library = ctypes.cdll.LoadLibrary(so_file)


@dataclass
class Metadata:
    """Extra information returned by the ACME server."""

    stable_url: str
    url: str
    domain: str


@dataclass
class RequestCertificateResponse:
    """The class that lego returns when issuing certificates correctly."""

    csr: str
    private_key: str
    certificate: str
    issuer_certificate: str
    metadata: Metadata


class RequestCertificateError(Exception):
    """Exceptions that are returned from the LEGO Go library."""


def request_certificate(
    email: str, server: str, csr: bytes, env: dict[str, str], plugin: str = ""
) -> RequestCertificateResponse:
    """Request a certificate from a given server using the LEGO acme library. Read more at https://go-acme.github.io.

    Args:
        email: the email to be used for registration
        server: the server to be used for requesting a certificate that implements the ACME protocol
        csr: the csr to be signed
        plugin: which DNS provider plugin to use for the request. Find yours at https://go-acme.github.io/lego/dns/.
        env: the environment variables required for the chosen plugin.
    """
    library.RequestCertificate.restype = ctypes.c_char_p
    library.RequestCertificate.argtypes = [ctypes.c_char_p]

    message = bytes(
        json.dumps(
            {
                "email": email,
                "server": server,
                "csr": csr.decode(),
                "plugin": plugin,
                "env": env,
            }
        ),
        "utf-8",
    )
    result: bytes = library.RequestCertificate(message)
    if result.startswith(b"error:"):
        raise RequestCertificateError(result.decode())
    result_dict = json.loads(result.decode("utf-8"))
    return RequestCertificateResponse(
        **{**result_dict, "metadata": Metadata(**result_dict.get("metadata"))}
    )


def validate_dns_plugin(plugin_name: str, plugin_options: dict[str, str]) -> str:
    """Validate the options that will be used for the plugin.

    Args:
        plugin_name: the name of the chosen plugin to be validated
        plugin_options: the options that will be validated
    """
    library.ValidateDNSProvider.restype = ctypes.c_char_p
    library.ValidateDNSProvider.argtypes = [ctypes.c_char_p]

    message = bytes(
        json.dumps({"plugin_name": plugin_name, "plugin_options": plugin_options}),
        "utf-8",
    )
    result: bytes = library.ValidateDNSProvider(message)
    return result.decode()
