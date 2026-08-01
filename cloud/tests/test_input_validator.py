"""Tests for the input validation module."""
from __future__ import annotations

from pathlib import Path

import pytest

from cloud.input_validator import (
    ValidationError,
    sanitize_evidence,
    validate_aws_profile,
    validate_aws_region,
    validate_control_id,
    validate_endpoint,
    validate_endpoints,
    validate_file_size,
    validate_hostname,
    validate_path,
    validate_port,
    validate_webhook_url,
)


class TestValidatePath:
    def test_valid_path(self, tmp_path):
        """Should accept valid existing paths."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        result = validate_path(str(test_file), must_exist=True)
        assert result == test_file.resolve()

    def test_rejects_empty_path(self):
        """Should reject empty paths."""
        with pytest.raises(ValidationError, match="empty"):
            validate_path("")

    def test_rejects_null_bytes(self):
        """Should reject paths with null bytes."""
        with pytest.raises(ValidationError, match="null"):
            validate_path("/tmp/test\x00.txt")

    def test_rejects_nonexistent_when_required(self):
        """Should reject nonexistent paths when must_exist=True."""
        with pytest.raises(ValidationError, match="does not exist"):
            validate_path("/nonexistent/path/xyz", must_exist=True)

    def test_allows_nonexistent_by_default(self):
        """Should allow nonexistent paths by default."""
        result = validate_path("/tmp/potentially_new_file.txt")
        assert isinstance(result, Path)


class TestValidateHostname:
    def test_valid_hostname(self):
        """Should accept valid hostnames."""
        assert validate_hostname("example.com") == "example.com"
        assert validate_hostname("api.example.com") == "api.example.com"

    def test_valid_ip_address(self):
        """Should accept valid IP addresses."""
        assert validate_hostname("192.168.1.1") == "192.168.1.1"
        assert validate_hostname("::1") == "::1"

    def test_rejects_empty(self):
        """Should reject empty hostname."""
        with pytest.raises(ValidationError, match="empty"):
            validate_hostname("")

    def test_rejects_too_long(self):
        """Should reject hostname exceeding max length."""
        with pytest.raises(ValidationError, match="maximum length"):
            validate_hostname("a" * 254)

    def test_rejects_invalid_chars(self):
        """Should reject hostnames with invalid characters."""
        with pytest.raises(ValidationError, match="Invalid"):
            validate_hostname("host name with spaces")


class TestValidatePort:
    def test_valid_ports(self):
        """Should accept valid port numbers."""
        assert validate_port(443) == 443
        assert validate_port("8080") == 8080
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_rejects_zero(self):
        """Should reject port 0."""
        with pytest.raises(ValidationError, match="between 1"):
            validate_port(0)

    def test_rejects_over_max(self):
        """Should reject ports over 65535."""
        with pytest.raises(ValidationError, match="between 1"):
            validate_port(65536)

    def test_rejects_non_numeric(self):
        """Should reject non-numeric ports."""
        with pytest.raises(ValidationError, match="Invalid"):
            validate_port("abc")


class TestValidateEndpoint:
    def test_valid_endpoint(self):
        """Should parse valid endpoints."""
        host, port = validate_endpoint("example.com:443")
        assert host == "example.com"
        assert port == 443

    def test_rejects_no_port(self):
        """Should reject endpoints without port."""
        with pytest.raises(ValidationError, match="host:port"):
            validate_endpoint("example.com")

    def test_rejects_empty(self):
        """Should reject empty endpoint."""
        with pytest.raises(ValidationError, match="empty"):
            validate_endpoint("")


class TestValidateEndpoints:
    def test_multiple_endpoints(self):
        """Should parse multiple endpoints."""
        result = validate_endpoints("a.com:443,b.com:8080")
        assert len(result) == 2
        assert result[0] == ("a.com", 443)
        assert result[1] == ("b.com", 8080)

    def test_rejects_empty(self):
        """Should reject empty string."""
        with pytest.raises(ValidationError, match="empty"):
            validate_endpoints("")

    def test_rejects_too_many(self):
        """Should reject more than 1000 endpoints."""
        many = ",".join(f"host{i}.com:443" for i in range(1001))
        with pytest.raises(ValidationError, match="Too many"):
            validate_endpoints(many)


class TestValidateControlId:
    def test_valid_ids(self):
        """Should accept valid control IDs."""
        assert validate_control_id("AWS-S3-001") == "AWS-S3-001"
        assert validate_control_id("K8S-NET-001") == "K8S-NET-001"
        assert validate_control_id("CUSTOM-DNS-001") == "CUSTOM-DNS-001"

    def test_rejects_empty(self):
        """Should reject empty control ID."""
        with pytest.raises(ValidationError, match="empty"):
            validate_control_id("")

    def test_rejects_lowercase(self):
        """Should reject lowercase control IDs."""
        with pytest.raises(ValidationError, match="pattern"):
            validate_control_id("aws-s3-001")


class TestValidateAwsProfile:
    def test_valid_profiles(self):
        """Should accept valid profile names."""
        assert validate_aws_profile("default") == "default"
        assert validate_aws_profile("production") == "production"
        assert validate_aws_profile("my-org/role") == "my-org/role"

    def test_rejects_empty(self):
        """Should reject empty profile."""
        with pytest.raises(ValidationError, match="empty"):
            validate_aws_profile("")

    def test_rejects_special_chars(self):
        """Should reject profiles with special characters."""
        with pytest.raises(ValidationError, match="Invalid"):
            validate_aws_profile("profile; rm -rf /")


class TestValidateAwsRegion:
    def test_valid_regions(self):
        """Should accept valid AWS regions."""
        assert validate_aws_region("us-east-1") == "us-east-1"
        assert validate_aws_region("ap-southeast-1") == "ap-southeast-1"
        assert validate_aws_region("eu-west-1") == "eu-west-1"

    def test_rejects_invalid(self):
        """Should reject invalid region formats."""
        with pytest.raises(ValidationError, match="Invalid"):
            validate_aws_region("not-a-region")


class TestValidateWebhookUrl:
    def test_valid_https_url(self):
        """Should accept valid HTTPS URLs."""
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        assert validate_webhook_url(url) == url

    def test_rejects_http(self):
        """Should reject HTTP URLs."""
        with pytest.raises(ValidationError, match="HTTPS"):
            validate_webhook_url("http://example.com/webhook")

    def test_rejects_private_ip(self):
        """Should reject private IPs (SSRF protection)."""
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://192.168.1.1/webhook")

    def test_rejects_loopback(self):
        """Should reject loopback addresses."""
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://127.0.0.1/webhook")

    def test_rejects_empty(self):
        """Should reject empty URL."""
        with pytest.raises(ValidationError, match="empty"):
            validate_webhook_url("")

    def test_rejects_dns_rebinding_to_private_ip(self, monkeypatch):
        """Should reject a public-looking hostname that resolves to a
        private address (DNS rebinding attack)."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://evil-rebind.example.com/webhook")

    def test_rejects_dns_rebinding_to_loopback(self, monkeypatch):
        """Should reject a hostname resolving to loopback."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://sneaky.example.com/webhook")

    def test_rejects_dns_rebinding_to_link_local(self, monkeypatch):
        """Should reject a hostname resolving to a link-local/metadata
        address (e.g. cloud metadata service 169.254.169.254)."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("169.254.169.254", 0),
                ),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://metadata.example.com/webhook")

    def test_accepts_hostname_resolving_to_public_ip(self, monkeypatch):
        """Should accept a hostname that resolves to a public address."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        url = "https://public.example.com/webhook"
        assert validate_webhook_url(url) == url

    def test_rejects_unresolvable_hostname(self, monkeypatch):
        """Should reject a hostname that fails DNS resolution."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="resolve"):
            validate_webhook_url("https://nonexistent.invalid/webhook")

    def test_rejects_multicast_ip(self):
        """Should reject literal multicast IPs."""
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://224.0.0.1/webhook")

    def test_rejects_invalid_hostname_format(self):
        """Should reject a URL whose hostname fails format validation."""
        with pytest.raises(ValidationError, match="Invalid hostname"):
            validate_webhook_url("https://exa_mple..com/webhook")

    def test_one_malicious_ip_among_many_is_blocked(self, monkeypatch):
        """If any resolved address is private, the whole hostname is
        blocked even if other addresses are public (DNS rebinding via
        multiple A/AAAA records)."""
        import socket

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValidationError, match="non-public"):
            validate_webhook_url("https://multi-record.example.com/webhook")


class TestValidateFileSize:
    def test_within_limit(self, tmp_path):
        """Should pass for files within limit."""
        f = tmp_path / "small.txt"
        f.write_text("hello")
        validate_file_size(f, max_size=1024)  # Should not raise

    def test_exceeds_limit(self, tmp_path):
        """Should fail for files exceeding limit."""
        f = tmp_path / "large.txt"
        f.write_text("x" * 2000)
        with pytest.raises(ValidationError, match="exceeds"):
            validate_file_size(f, max_size=1000)


class TestSanitizeEvidence:
    def test_removes_control_chars(self):
        """Should remove control characters."""
        result = sanitize_evidence("hello\x00world\x01")
        assert "\x00" not in result
        assert "\x01" not in result
        assert "helloworld" in result

    def test_preserves_normal_text(self):
        """Should preserve normal text."""
        text = "status=pass, resource=arn:aws:s3:::bucket"
        assert sanitize_evidence(text) == text

    def test_truncates_long_text(self):
        """Should truncate to max length."""
        long_text = "a" * 1000
        result = sanitize_evidence(long_text, max_length=100)
        assert len(result) == 100

    def test_handles_empty(self):
        """Should handle empty string."""
        assert sanitize_evidence("") == ""
