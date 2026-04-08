"""Unit tests for pylego dataclasses and error handling."""

import json
from unittest.mock import MagicMock, patch

import pytest

from pylego import LEGOError, LEGOResponse
from pylego.pylego import Identifier, LEGOResponse, Metadata, Subproblem, run_lego_command


class TestLEGOError:
    def test_given_detail_only_when_creating_error_then_defaults_are_set(self):
        err = LEGOError("something failed")
        assert str(err) == "something failed"
        assert err.detail == "something failed"
        assert err.type == "lego"
        assert err.code == ""
        assert err.status is None
        assert err.subproblems == []
        assert err.info == {}

    def test_given_code_provided_when_creating_error_then_message_includes_code(self):
        err = LEGOError("bad request", code="invalid_csr")
        assert str(err) == "[invalid_csr] bad request"
        assert err.code == "invalid_csr"

    def test_given_acme_params_when_creating_error_then_all_fields_are_set(self):
        err = LEGOError(
            "unauthorized",
            type="acme",
            code="unauthorized",
            status=403,
            acme_type="urn:ietf:params:acme:error:unauthorized",
            subproblems=[
                Subproblem(
                    type="unauthorized",
                    detail="invalid token",
                    identifier=Identifier(type="dns", value="example.com"),
                )
            ],
            info={"key": "value"},
        )
        assert err.type == "acme"
        assert err.status == 403
        assert err.acme_type == "urn:ietf:params:acme:error:unauthorized"
        assert len(err.subproblems) == 1
        assert err.subproblems[0].identifier.value == "example.com"
        assert err.info == {"key": "value"}

    def test_given_lego_error_when_raised_then_caught_as_exception(self):
        with pytest.raises(LEGOError, match="test error"):
            raise LEGOError("test error")


class TestDataclasses:
    def test_given_dns_type_when_creating_identifier_then_fields_are_set(self):
        ident = Identifier(type="dns", value="example.com")
        assert ident.type == "dns"
        assert ident.value == "example.com"

    def test_given_subproblem_data_when_creating_subproblem_then_fields_are_set(self):
        sub = Subproblem(
            type="unauthorized",
            detail="bad token",
            identifier=Identifier(type="ip", value="1.2.3.4"),
        )
        assert sub.type == "unauthorized"
        assert sub.identifier.type == "ip"

    def test_given_metadata_args_when_creating_metadata_then_fields_are_set(self):
        meta = Metadata(stable_url="https://acme.example", url="https://acme.example/cert", domain="example.com")
        assert meta.domain == "example.com"

    def test_given_valid_data_when_creating_lego_response_then_fields_are_set(self):
        resp = LEGOResponse(
            csr="csr_data",
            private_key="key_data",
            certificate="cert_data",
            issuer_certificate="issuer_data",
            metadata=Metadata(stable_url="https://a", url="https://b", domain="example.com"),
        )
        assert resp.certificate == "cert_data"
        assert resp.metadata.domain == "example.com"


class TestRunLegoCommand:
    def test_given_negative_propagation_wait_when_running_command_then_value_error_raised(self):
        with pytest.raises(ValueError, match="dns_propagation_wait cannot be negative"):
            run_lego_command(
                email="test@example.com",
                server="https://acme.example",
                csr=b"fake-csr",
                env={},
                dns_propagation_wait=-1,
            )

    @patch("pylego.pylego.library")
    def test_given_valid_request_when_lego_succeeds_then_response_returned(self, mock_library):
        mock_library.RunLegoCommand.return_value = json.dumps({
            "success": True,
            "data": {
                "csr": "test_csr",
                "private_key": "test_key",
                "certificate": "test_cert",
                "issuer_certificate": "test_issuer",
                "metadata": {
                    "stable_url": "https://stable",
                    "url": "https://url",
                    "domain": "example.com",
                },
            },
        }).encode()

        result = run_lego_command(
            email="test@example.com",
            server="https://acme.example",
            csr=b"fake-csr",
            env={"KEY": "val"},
        )
        assert isinstance(result, LEGOResponse)
        assert result.certificate == "test_cert"
        assert result.metadata.domain == "example.com"

    @patch("pylego.pylego.library")
    def test_given_failed_request_when_lego_returns_error_then_lego_error_raised(self, mock_library):
        mock_library.RunLegoCommand.return_value = json.dumps({
            "success": False,
            "error": {
                "type": "lego",
                "detail": "something went wrong",
                "code": "bad_request",
            },
        }).encode()

        with pytest.raises(LEGOError, match="something went wrong") as exc_info:
            run_lego_command(
                email="test@example.com",
                server="https://acme.example",
                csr=b"fake-csr",
                env={},
            )
        assert exc_info.value.type == "lego"
        assert exc_info.value.code == "bad_request"

    @patch("pylego.pylego.library")
    def test_given_acme_failure_when_lego_returns_subproblems_then_error_contains_subproblems(self, mock_library):
        mock_library.RunLegoCommand.return_value = json.dumps({
            "success": False,
            "error": {
                "type": "acme",
                "detail": "unauthorized",
                "code": "unauthorized",
                "status": 403,
                "acme_type": "urn:ietf:params:acme:error:unauthorized",
                "subproblems": [
                    {
                        "type": "unauthorized",
                        "detail": "invalid token",
                        "identifier": {"type": "dns", "value": "example.com"},
                    }
                ],
            },
        }).encode()

        with pytest.raises(LEGOError) as exc_info:
            run_lego_command(
                email="test@example.com",
                server="https://acme.example",
                csr=b"fake-csr",
                env={},
            )
        err = exc_info.value
        assert err.type == "acme"
        assert err.status == 403
        assert len(err.subproblems) == 1
        assert err.subproblems[0].identifier.value == "example.com"

    @patch("pylego.pylego.library")
    def test_given_invalid_json_when_lego_responds_then_parse_error_raised(self, mock_library):
        mock_library.RunLegoCommand.return_value = b"not json"

        with pytest.raises(LEGOError, match="Failed to parse response"):
            run_lego_command(
                email="test@example.com",
                server="https://acme.example",
                csr=b"fake-csr",
                env={},
            )

    @patch("pylego.pylego.library")
    def test_given_dns_options_when_running_command_then_options_passed_to_lego(self, mock_library):
        mock_library.RunLegoCommand.return_value = json.dumps({
            "success": True,
            "data": {
                "csr": "c", "private_key": "k", "certificate": "cert",
                "issuer_certificate": "i",
                "metadata": {"stable_url": "s", "url": "u", "domain": "d"},
            },
        }).encode()

        run_lego_command(
            email="e@e.com",
            server="https://s",
            csr=b"csr",
            env={},
            dns_propagation_wait=60,
            dns_nameservers=["8.8.8.8:53"],
        )

        call_args = mock_library.RunLegoCommand.call_args[0][0]
        payload = json.loads(call_args)
        assert payload["dns_propagation_wait"] == 60
        assert payload["dns_nameservers"] == ["8.8.8.8:53"]
