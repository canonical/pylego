import os
import subprocess
import time

import pytest
import requests
from pylego import run_lego_command


class TestPyLego:
    @pytest.fixture(scope="session")
    def configure_acme_server():
        """Get and install pebble, a lightweight ACME server from letsencrypt."""
        tests_dir = os.path.dirname(__file__)

        subprocess.check_call(
            ["go", "install", "./cmd/pebble"], cwd=os.path.join(tests_dir, "pebble")
        )
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
