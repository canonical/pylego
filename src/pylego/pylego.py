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
class LEGOResponse:
    """The class that lego returns when issuing certificates correctly."""

    csr: str
    private_key: str
    certificate: str
    issuer_certificate: str
    metadata: Metadata


class LEGOError(Exception):
    """Exceptions that are returned from the LEGO Go library."""


def run_lego_command(
    email: str, server: str, csr: bytes, env: dict[str, str], plugin: str = "", private_key: str = ""
) -> LEGOResponse:
    """Run an arbitrary command in the Lego application. Read more at https://go-acme.github.io.

    Args:
        email: the email to be used for registration
        server: the server to be used for requesting a certificate that implements the ACME protocol
        csr: the csr to be signed
        plugin: which DNS provider plugin to use for the request. Find yours at https://go-acme.github.io/lego/dns/.
        env: the environment variables required for the chosen plugin.
        private_key: the private key to be used for the registration on the ACME server (not the private key used to sign the CSR).
            If not provided, a new one will be generated.
    """
    library.RunLegoCommand.restype = ctypes.c_char_p
    library.RunLegoCommand.argtypes = [ctypes.c_char_p]

    message = bytes(
        json.dumps(
            {
                "email": email,
                "server": server,
                "csr": csr.decode(),
                "plugin": plugin,
                "env": env,
                "private_key": private_key,
            }
        ),
        "utf-8",
    )
    result: bytes = library.RunLegoCommand(message)
    if result.startswith(b"error:"):
        raise LEGOError(result.decode())
    result_dict = json.loads(result.decode("utf-8"))
    return LEGOResponse(**{**result_dict, "metadata": Metadata(**result_dict.get("metadata"))})
