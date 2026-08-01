"""Network and TLS endpoint scanner with input validation and rate limiting.

Scans endpoints for TLS version compliance, certificate validity,
and unexpected open ports.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from cloud.core import Finding, Severity, Status
from cloud.input_validator import ValidationError, validate_endpoints
from cloud.logging_config import get_logger
from cloud.rate_limiter import RateLimiter

logger = get_logger("network_scanner")

CONTROL_IDS = {"NET-TLS-001", "NET-TLS-002", "NET-PORT-001"}

# Rate limit network scans to prevent abuse
_SCAN_RATE_LIMITER = RateLimiter(calls_per_second=5.0, burst=10)

# Connection timeouts
_CONNECT_TIMEOUT = 10
_PORT_SCAN_TIMEOUT = 5


def _finding(control_id: str, title: str, status: Status, severity: Severity,
             resource: str, evidence: str, remediation: str = "") -> Finding:
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _check_tls_version(host: str, port: int) -> Finding:
    """NET-TLS-001: TLS 1.2 or higher."""
    if not _SCAN_RATE_LIMITER.acquire(timeout=30):
        return _finding(
            "NET-TLS-001", "TLS 1.2 or higher",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            "Rate limiter timeout: too many concurrent scans",
            "Reduce scan concurrency or endpoint count.",
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Explicitly disable older TLS versions for test — we only want to see what server offers
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                # TLSv1.2 and TLSv1.3 are acceptable
                ok = version in ("TLSv1.2", "TLSv1.3")
                return _finding(
                    "NET-TLS-001", "TLS 1.2 or higher",
                    Status.PASS if ok else Status.FAIL,
                    Severity.HIGH, f"{host}:{port}",
                    f"tls_version={version}",
                    "Upgrade server to TLS 1.2+.",
                )
    except TimeoutError:
        return _finding(
            "NET-TLS-001", "TLS 1.2 or higher",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"Connection timed out after {_CONNECT_TIMEOUT}s",
            "Verify the endpoint is accessible and not firewalled.",
        )
    except Exception as exc:
        return _finding(
            "NET-TLS-001", "TLS 1.2 or higher",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"{type(exc).__name__}: {exc}",
        )


def _check_cert_validity(host: str, port: int) -> Finding:
    """NET-TLS-002: Valid certificate."""
    if not _SCAN_RATE_LIMITER.acquire(timeout=30):
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            "Rate limiter timeout: too many concurrent scans",
            "Reduce scan concurrency or endpoint count.",
        )
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                subject = cert.get("subject", "unknown")
                not_after = cert.get("notAfter", "unknown")
                return _finding(
                    "NET-TLS-002", "Valid TLS certificate",
                    Status.PASS, Severity.HIGH, f"{host}:{port}",
                    f"subject={subject}, expires={not_after}",
                )
    except ssl.SSLCertVerificationError as exc:
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.FAIL, Severity.HIGH, f"{host}:{port}",
            f"cert_error={exc.verify_message}",
            "Fix or renew the TLS certificate.",
        )
    except TimeoutError:
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"Connection timed out after {_CONNECT_TIMEOUT}s",
        )
    except Exception as exc:
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"{type(exc).__name__}: {exc}",
        )


def _check_open_ports(
    host: str, ports: list[int], expected: set[int]
) -> list[Finding]:
    """NET-PORT-001: Unexpected open ports."""
    findings: list[Finding] = []
    for port in ports:
        if port in expected:
            continue
        if not _SCAN_RATE_LIMITER.acquire(timeout=30):
            findings.append(_finding(
                "NET-PORT-001", "Unexpected open port",
                Status.ERROR, Severity.HIGH, f"{host}:{port}",
                "Rate limiter timeout during port scan",
                "Reduce scan concurrency.",
            ))
            continue
        try:
            with socket.create_connection(
                (host, port), timeout=_PORT_SCAN_TIMEOUT
            ):
                findings.append(_finding(
                    "NET-PORT-001", "Unexpected open port",
                    Status.FAIL, Severity.MEDIUM, f"{host}:{port}",
                    f"port={port} is open and not expected",
                    "Close or firewall unexpected ports.",
                ))
        except (TimeoutError, OSError):
            pass
    if not findings:
        findings.append(_finding(
            "NET-PORT-001", "No unexpected open ports",
            Status.PASS, Severity.MEDIUM, host,
            "all_ports_expected=true",
        ))
    return findings


def scan_endpoints(endpoints: list[tuple[str, int]], args: Any) -> list[Finding]:
    """Scan validated endpoints for TLS compliance.

    Args:
        endpoints: List of validated (host, port) tuples.
        args: CLI arguments namespace.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []
    max_workers = min(getattr(args, "workers", 8), len(endpoints), 16)

    logger.info("Scanning %d endpoints with %d workers", len(endpoints), max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for host, port in endpoints:
            futures.append(executor.submit(_check_tls_version, host, port))
            futures.append(executor.submit(_check_cert_validity, host, port))

        for future in as_completed(futures):
            try:
                findings.append(future.result())
            except Exception as exc:
                logger.error("Endpoint check failed: %s", exc)
                findings.append(_finding(
                    "NET-TLS-001", "Endpoint scan error",
                    Status.ERROR, Severity.HIGH, "network:unknown",
                    f"{type(exc).__name__}: {exc}",
                ))

    logger.info("Network scan complete: %d findings", len(findings))
    return findings


def run_audit(args: Any) -> list[Finding]:
    """Run the network/TLS audit.

    Args:
        args: CLI arguments namespace with 'endpoints' attribute.

    Returns:
        List of findings.
    """
    endpoints_raw = getattr(args, "endpoints", None)
    if isinstance(endpoints_raw, str):
        endpoints_raw = endpoints_raw.strip()

    if not endpoints_raw:
        return [_finding(
            "NET-TLS-001", "No endpoints specified",
            Status.ERROR, Severity.HIGH, "network:config",
            "Provide --endpoints host:port[,host:port,...]",
            "Specify endpoints to scan.",
        )]

    # Validate all endpoints
    try:
        validated_endpoints = validate_endpoints(endpoints_raw)
    except ValidationError as exc:
        return [_finding(
            "NET-TLS-001", "Endpoint validation failed",
            Status.ERROR, Severity.HIGH, "network:config",
            str(exc),
            "Provide valid host:port endpoints.",
        )]

    return scan_endpoints(validated_endpoints, args)
