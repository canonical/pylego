import os
import subprocess
import time

import pytest
import requests

from pylego import request_certificate, validate_dns_plugin


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


class TestPyLego:
    def test_given_request_certificate_when_request_sent_then_certificate_issued(
        self,
        configure_acme_server: dict[str, str | bytes],
    ):
        response = request_certificate(
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

    @pytest.mark.parametrize(
        "input_args,expected_output",
        [
            ({"plugin_name": "nonexistentplugin", "plugin_options": {"api": "key"}}, "error: couldn't validate provider: unrecognized DNS provider: nonexistentplugin"),
            ({"plugin_name": "route53", "plugin_options": {}}, ""),
            ({"plugin_name": "route53", "plugin_options": {"api": "key"}}, ""),
            ({"plugin_name": "route53", "plugin_options": {"REAL_VALUE??": "key"}}, ""),
        ],
    )
    def test_given_plugin_data_when_validated_then_expected_response_returned(
        self, input_args, expected_output
    ):
        plugin_name = input_args.get("plugin_name", "")
        plugin_options = input_args.get("plugin_options", "")
        response = validate_dns_plugin(plugin_name, plugin_options)
        assert response == expected_output


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
