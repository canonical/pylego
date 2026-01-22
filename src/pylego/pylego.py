"""Python interface that wraps the lego application CLI."""

import ctypes
import json
from dataclasses import dataclass
from pathlib import Path

here = Path(__file__).absolute().parent
so_file = here / ("lego.so")
library = ctypes.cdll.LoadLibrary(so_file)


@dataclass
class Identifier:
    """ACME identifier (domain or IP)."""

    type: str  # "dns" or "ip"
    value: str  # Domain name or IP address


@dataclass
class Subproblem:
    """ACME subproblem details."""

    type: str  # Error type (e.g., "unauthorized", "dns")
    detail: str  # Human-readable message
    identifier: Identifier  # The identifier that caused this subproblem


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
    """Unified exception for all errors returned by the lego invocation.

    Attributes:
        type: source of the error. "acme" when coming from the ACME server, otherwise "lego".
        code: error code/category. For ACME, this is derived from the ACME problem type; otherwise, it's set by lego.
        status: HTTP status code for ACME errors, None otherwise.
        detail: human-readable description of the error.
        acme_type: full ACME problem type (URN), present only for ACME errors.
        subproblems: list of Subproblem objects with detailed error information.
        info: dictionary with the raw error information returned by the underlying call.
    """

    def __init__(
        self,
        detail: str,
        *,
        type: str = "lego",
        code: str = "",
        status: int | None = None,
        acme_type: str = "",
        subproblems: list[Subproblem] | None = None,
        info: dict | None = None,
    ):
        # Include code in exception message for better error display
        message = f"[{code}] {detail}" if code else detail
        super().__init__(message)
        self.type = type
        self.code = code
        self.status = status
        self.detail = detail
        self.acme_type = acme_type
        self.subproblems = subproblems or []
        self.info = info or {}


def run_lego_command(
    email: str,
    server: str,
    csr: bytes,
    env: dict[str, str],
    plugin: str = "",
    private_key: str = "",
    dns_propagation_wait: int | None = None,
    dns_nameservers: list[str] | None = None,
) -> LEGOResponse:
    """Run an arbitrary command in the Lego application. Read more at https://go-acme.github.io.

    Args:
        email: the email to be used for registration
        server: the server to be used for requesting a certificate that implements the ACME protocol
        csr: the csr to be signed
        plugin: provider to use. One of: "http" (HTTP-01), "tls" (TLS-ALPN-01), or any LEGO DNS provider from https://go-acme.github.io/lego/dns/.
        env: the environment variables required for the chosen plugin.
        private_key: the private key to be used for the registration on the ACME server (not the private key used to sign the CSR).
            If not provided, a new one will be generated.
        dns_propagation_wait: optional wait duration for DNS propagation, in seconds (int).
        dns_nameservers: optional list of DNS nameserver addresses to use for DNS-01 challenge verification.
            Can include ports (e.g., ["8.8.8.8:53", "8.8.4.4:53"]) or just IP addresses (port 53 assumed).
    """
    library.RunLegoCommand.restype = ctypes.c_char_p
    library.RunLegoCommand.argtypes = [ctypes.c_char_p]

    if dns_propagation_wait is not None and dns_propagation_wait < 0:
        raise ValueError("dns_propagation_wait cannot be negative")

    payload = {
        "email": email,
        "server": server,
        "csr": csr.decode(),
        "plugin": plugin,
        "env": env,
        "private_key": private_key,
    }
    if dns_propagation_wait is not None:
        payload["dns_propagation_wait"] = dns_propagation_wait
    if dns_nameservers is not None:
        payload["dns_nameservers"] = dns_nameservers

    message = bytes(
        json.dumps(payload),
        "utf-8",
    )
    result: bytes = library.RunLegoCommand(message)
    result_str = result.decode("utf-8")

    try:
        result_dict = json.loads(result_str)
    except json.JSONDecodeError as e:
        raise LEGOError(f"Failed to parse response: {result_str}") from e

    if not result_dict.get("success", False):
        error_info: dict = result_dict.get("error", {})
        err_source = error_info.get("type", "lego")
        detail = error_info.get("detail", "Unknown error occurred")

        subproblems = []
        for sub_dict in error_info.get("subproblems", []):
            identifier_dict = sub_dict.get("identifier", {})
            subproblems.append(
                Subproblem(
                    type=sub_dict.get("type", ""),
                    detail=sub_dict.get("detail", ""),
                    identifier=Identifier(
                        type=identifier_dict.get("type", ""),
                        value=identifier_dict.get("value", ""),
                    ),
                )
            )

        info = dict(error_info)
        raise LEGOError(
            detail,
            type="acme" if err_source == "acme" else "lego",
            code=error_info.get("code", ""),
            status=error_info.get("status"),
            acme_type=error_info.get("acme_type", "") if err_source == "acme" else "",
            subproblems=subproblems,
            info=info,
        )

    data = result_dict.get("data", {})
    return LEGOResponse(**{**data, "metadata": Metadata(**data.get("metadata", {}))})
