import os
import subprocess
import time

import pytest
import requests

from pylego import LEGOError, run_lego_command


@pytest.fixture(scope="session")
def configure_acme_server():
    """Get and install pebble, a lightweight ACME server from letsencrypt."""
    tests_dir = os.path.dirname(__file__)

    subprocess.check_call(["go", "install", "./cmd/pebble"], cwd=os.path.join(tests_dir, "pebble"))
    pebble = subprocess.Popen(
        ["pebble", "-config", "test/config/pebble-config.json"],
        cwd=os.path.join(tests_dir, "pebble"),
    )

    ca_path = os.path.join(tests_dir, "pebble/test/certs/pebble.minica.pem")
    filename = os.path.join(tests_dir, "test_files/test.csr")
    localhost_csr = open(filename).read().encode()

    poll_server("https://0.0.0.0:14000/dir")

    yield {"csr": localhost_csr, "ca_path": ca_path}

    pebble.terminate()

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAt3t/4pj0y2KIgDQPfglKWecqvfL4C+hwgIV/+E4BAmRpkcNG
Dt4V7EcjaMKBfvjU+IoQu/AezsXgvs4pEXUwIi87T0e1zUQyl2H4K7x9n68LuaK4
+luDZnPZKv7vnKEMBr8+Flb2L21vcO7dTXYM0/18lcSqdDL3iq8aiUNx6lZkfz0M
4UIbvfDB9ICatsqn+H1uUE58NBnDwomU/IPXbfOj25VRwfBZhWgNX9+N7EDR9dvE
FqwWPkA/6/IbZA4pWQmH+e/9KEoTn2JLH6SNFw1pQyhwTHpwRGuMJQqPLLDFY1CS
Ds5lWym4+ZJ8n2Aovrl3Iik0b5bR4xJ2b8pByQIDAQABAoIBAFgoWgdFZ6TLGHvE
x8bObu9oTxSKB50tFtThj919mSWNml2jPeeJ1G28tmowvmiD5Uvvhl/OXPcLg1Ma
Gghdzn02RWBvu42/HTG4LDXTcGaHg/IzGX6M9sMEmYz7haQziuQ5AftY2BtskNVp
p2H+/OXkTvZk0mNXU7HKNU1LXxHwlSVe4H3x/VSqvBsm8oTqf3PCExKwl+Hyl5oM
O01pbVF9ySCegbSOatPf6qhurpo76Tykg7lNAZ2OFs9G0RiAe4OpweUaCiALLyLv
hXr09bsYYG7R43KHpZ/FzIFBZTQ+XrqN48gGwAcarQGlQutzepB39HMGdBIkHVEd
aMqLt4sCgYEA36Capmzt+wWgaFcuI9Wi4Q/jsiyf+o8Cvd9eQXWrOppfNPQvjZdx
ZDK+uZ32Jhj5K5FZ3vf7bmBFeY+ykR8ccWBIUf5qLF+Mq8PkL8kTCEjhEELg1hnl
zyRhk3jqE/UzqoHvleY7STrr2CH/YS7dP/2f++l+tk3qw87QuDJBMecCgYEA0gsq
fymr4mPy5en+yh11i4y7Woh4rWuXTyY47cyvRA9teC5Sd5oGkzEm36rDVCKfwSbj
cX0z9IQLXXgCzmyW27CAazLBC2Nioysh4JIratA+2N4My9Tj5z8kBYRqvI9jninZ
KMKVik/3iXuvBVYkh0jj0PGYQJt7Tdgz/O5I2M8CgYAEKpTXBu6EH722U/F7H27S
bJ5cYnJ0k5eEfBXgeFXBWMDvVqFQLQMiz8M36BZ+7TYvNp0LB2m6y7Zfpmq4Q3Ef
N6EBThEiVIFlbdfhgAiHvfvbdrODqaXbbx0WR0ltJ8NXqOYSz+BI4/0i4LdGUz4y
BAKoCdifguId1cuTsvP9/wKBgHYDXA8yhKagbZsMS+GXh7Gukp2dS+B0MQGBgj7p
4Bena2Q48pDMc6FD3omQ0kp1YbkOdoAPTp+1iQUtJraAgIpSsvSIAbq6TnNLCq+4
sLhE5OrIZ/wmUx5cdYq8CZSEI/57mM2z9n1NzNDsMzwWWFPCem2tMFQsh60HKr6T
y041AoGAL2Nyf9ByLfstEZQwiPj3YkmrAqXFIzo+4pkHkoMyN/Hh6/kQTI1grexH
CgNNhc9eVFyhxtc+fkEj01GPNyBWNolCKRbsEyNxyXwkqiKJk2m6VE0k9RfL48CE
GcIJgK4LGOTetSPQ1I+DQrAgNN/MRakmi1uBzKsVLpqIp+YO5kA=
-----END RSA PRIVATE KEY-----
"""

class TestPyLego:
    def test_given_request_certificate_when_request_sent_then_certificate_issued(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        response = run_lego_command(
            email="something@nowhere.com",
            server="https://localhost:14000/dir",
            csr=configure_acme_server.get("csr"),
            env={
                "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                "HTTP01_PORT": "5002",
                "TLSALPN01_PORT": "5001",
            },
        )
        assert response.metadata.domain == "localhost"

    def test_given_request_certificate_with_rsa_private_key_when_request_sent_then_certificate_issued(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        response = run_lego_command(
            email="something@nowhere.com",
            server="https://localhost:14000/dir",
            csr=configure_acme_server.get("csr"),
            env={
                "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                "HTTP01_PORT": "5002",
                "TLSALPN01_PORT": "5001",
            },
            private_key=PRIVATE_KEY,
        )
        assert response.metadata.domain == "localhost"

    def test_given_invalid_private_key_when_request_sent_then_error_structure_correct(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        """Verify lego error structure has all expected fields populated correctly."""
        with pytest.raises(LEGOError) as exc_info:
            run_lego_command(
                email="something@nowhere.com",
                server="https://localhost:14000/dir",
                csr=configure_acme_server.get("csr"),
                env={
                    "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                    "HTTP01_PORT": "5002",
                    "TLSALPN01_PORT": "5001",
                },
                private_key="whatever private key",
            )
        error = exc_info.value
        assert error.type == "lego"
        assert error.code == "invalid_private_key"
        assert error.detail
        assert error.acme_type == ""
        assert error.status is None
        assert f"[{error.code}]" in str(error)

    def test_given_invalid_csr_when_request_sent_then_error_raised(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        with pytest.raises(LEGOError):
            run_lego_command(
                email="something@nowhere.com",
                server="https://localhost:14000/dir",
                csr=b"invalid csr content",
                env={
                    "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                    "HTTP01_PORT": "5002",
                    "TLSALPN01_PORT": "5001",
                },
            )

    def test_given_invalid_dns_provider_when_request_sent_then_error_raised(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        with pytest.raises(LEGOError):
            run_lego_command(
                email="something@nowhere.com",
                server="https://localhost:14000/dir",
                csr=configure_acme_server.get("csr"),
                plugin="nonexistent_provider",
                env={
                    "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                },
            )

    def test_given_negative_dns_propagation_wait_in_python_when_request_sent_then_value_error_raised(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        with pytest.raises(ValueError) as exc_info:
            run_lego_command(
                email="something@nowhere.com",
                server="https://localhost:14000/dir",
                csr=configure_acme_server.get("csr"),
                env={
                    "SSL_CERT_FILE": configure_acme_server.get("ca_path"),
                    "HTTP01_PORT": "5002",
                    "TLSALPN01_PORT": "5001",
                },
                dns_propagation_wait=-1,
            )
        assert "cannot be negative" in str(exc_info.value)


def poll_server(url: str, freq: int = 1, timeout: int = 60):
    while timeout > 0:
        try:
            time.sleep(freq)
            response = requests.get(url, verify=False)
            return response
        except requests.RequestException as e:
            print(e)
        timeout -= freq
    raise TimeoutError("Timed out waiting for pebble to become responsive")
