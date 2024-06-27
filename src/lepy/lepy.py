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
    stable_url: str
    url: str
    domain: str

@dataclass
class LEGOResponse:
    csr: str
    private_key: str
    certificate: str
    issuer_certificate: str
    metadata: Metadata

def run_lego_command(email: str, server: str, csr: bytes, plugin: str, env: dict[str, str]) -> str:
    """Run an arbitrary command in the Lego application. Read more at https://go-acme.github.io.

    Args:
        email: the email to be used for registration
        server: the server to be used for requesting a certificate that implements the ACME protocol
        csr: the csr to be signed
        plugin: which DNS provider plugin to use for the request. Find yours at https://go-acme.github.io/lego/dns/.
        env: the environment variables required for the chosen plugin.
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
            }
        ),
        "utf-8",
    )
    result: bytes = library.RunLegoCommand(message)
    return LEGOResponse(**json.loads(result.decode("utf-8")))

