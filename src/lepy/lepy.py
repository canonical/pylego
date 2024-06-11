"""Python interface that wraps the lego application CLI."""

import ctypes
import json
from pathlib import Path

here = Path(__file__).absolute().parent
so_file = here / ("lego.so")
library = ctypes.cdll.LoadLibrary(so_file)


def run_lego_command(
    email: str, server: str, csr_path: str, plugin: str, env: dict[str, str]
) -> str:
    """Run an arbitrary command in the Lego application. Read more at https://go-acme.github.io.

    Args:
        email: the email to be used for registration
        server: the server to be used for requesting a certificate that implements the ACME protocol
        csr_path: the path to the CSR file
        plugin: which DNS provider plugin to use for the request. Find yours at https://go-acme.github.io/lego/dns/.
        env: the environment variables required for the chosen plugin.
    """
    library.RunLegoCommand.restype = ctypes.c_int
    library.RunLegoCommand.argtypes = [ctypes.c_wchar_p]

    message = json.dumps(
        {
            "email": email,
            "server": server,
            "csr_path": csr_path,
            "plugin": plugin,
            "env": env,
        }
    )

    return library.RunLegoCommand(message)
