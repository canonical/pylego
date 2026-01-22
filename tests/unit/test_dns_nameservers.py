"""Unit tests for dns_nameservers parameter."""

import json
from unittest.mock import patch

from pylego import run_lego_command


class TestDNSNameserversParameter:
    """Test the dns_nameservers parameter."""

    @patch("pylego.pylego.library")
    def test_dns_nameservers_included_in_payload(self, mock_library):
        """Test that dns_nameservers are included in the JSON payload sent to Go."""
        # Setup mock
        mock_response = {
            "csr": "test_csr",
            "private_key": "test_key",
            "certificate": "test_cert",
            "issuer_certificate": "test_issuer",
            "metadata": {
                "stable_url": "https://example.com/stable",
                "url": "https://example.com/url",
                "domain": "example.com",
            },
        }
        mock_library.RunLegoCommand.return_value = json.dumps(mock_response).encode()

        # Call function with dns_nameservers
        nameservers = ["8.8.8.8", "8.8.4.4:53"]
        run_lego_command(
            email="test@example.com",
            server="https://acme.example.com/directory",
            csr=b"-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            env={"TEST_KEY": "TEST_VALUE"},
            plugin="cloudflare",
            dns_nameservers=nameservers,
        )

        # Verify the call
        mock_library.RunLegoCommand.assert_called_once()
        call_args = mock_library.RunLegoCommand.call_args[0][0]
        payload = json.loads(call_args.decode())

        # Verify dns_nameservers is in payload
        assert "dns_nameservers" in payload
        assert payload["dns_nameservers"] == nameservers

    @patch("pylego.pylego.library")
    def test_dns_nameservers_not_included_when_none(self, mock_library):
        """Test that dns_nameservers is not included when None."""
        # Setup mock
        mock_response = {
            "csr": "test_csr",
            "private_key": "test_key",
            "certificate": "test_cert",
            "issuer_certificate": "test_issuer",
            "metadata": {
                "stable_url": "https://example.com/stable",
                "url": "https://example.com/url",
                "domain": "example.com",
            },
        }
        mock_library.RunLegoCommand.return_value = json.dumps(mock_response).encode()

        # Call function without dns_nameservers
        run_lego_command(
            email="test@example.com",
            server="https://acme.example.com/directory",
            csr=b"-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            env={"TEST_KEY": "TEST_VALUE"},
            plugin="cloudflare",
        )

        # Verify the call
        mock_library.RunLegoCommand.assert_called_once()
        call_args = mock_library.RunLegoCommand.call_args[0][0]
        payload = json.loads(call_args.decode())

        # Verify dns_nameservers is not in payload
        assert "dns_nameservers" not in payload

    @patch("pylego.pylego.library")
    def test_dns_nameservers_with_empty_list(self, mock_library):
        """Test that empty list is handled correctly."""
        # Setup mock
        mock_response = {
            "csr": "test_csr",
            "private_key": "test_key",
            "certificate": "test_cert",
            "issuer_certificate": "test_issuer",
            "metadata": {
                "stable_url": "https://example.com/stable",
                "url": "https://example.com/url",
                "domain": "example.com",
            },
        }
        mock_library.RunLegoCommand.return_value = json.dumps(mock_response).encode()

        # Call function with empty dns_nameservers list
        run_lego_command(
            email="test@example.com",
            server="https://acme.example.com/directory",
            csr=b"-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            env={"TEST_KEY": "TEST_VALUE"},
            plugin="cloudflare",
            dns_nameservers=[],
        )

        # Verify the call
        mock_library.RunLegoCommand.assert_called_once()
        call_args = mock_library.RunLegoCommand.call_args[0][0]
        payload = json.loads(call_args.decode())

        # Verify dns_nameservers is in payload but empty
        assert "dns_nameservers" in payload
        assert payload["dns_nameservers"] == []

    @patch("pylego.pylego.library")
    def test_dns_nameservers_with_multiple_nameservers(self, mock_library):
        """Test with multiple nameservers including ports."""
        # Setup mock
        mock_response = {
            "csr": "test_csr",
            "private_key": "test_key",
            "certificate": "test_cert",
            "issuer_certificate": "test_issuer",
            "metadata": {
                "stable_url": "https://example.com/stable",
                "url": "https://example.com/url",
                "domain": "example.com",
            },
        }
        mock_library.RunLegoCommand.return_value = json.dumps(mock_response).encode()

        # Call function with multiple nameservers
        nameservers = ["127.0.0.53", "10.151.0.23", "8.8.8.8:53"]
        run_lego_command(
            email="test@example.com",
            server="https://acme.example.com/directory",
            csr=b"-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            env={"TEST_KEY": "TEST_VALUE"},
            plugin="cloudflare",
            dns_nameservers=nameservers,
        )

        # Verify the call
        mock_library.RunLegoCommand.assert_called_once()
        call_args = mock_library.RunLegoCommand.call_args[0][0]
        payload = json.loads(call_args.decode())

        # Verify dns_nameservers is in payload with all values
        assert "dns_nameservers" in payload
        assert payload["dns_nameservers"] == nameservers
        assert len(payload["dns_nameservers"]) == 3
