"""Webhook alert module — send findings alerts to Slack, Teams, PagerDuty.

Includes retry logic with exponential backoff, URL validation,
and secure payload handling.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from cloud.finding_utils import actionable_findings, finding_control_id
from cloud.input_validator import _is_unsafe_webhook_address, validate_webhook_url
from cloud.logging_config import get_logger
from cloud.rate_limiter import retry_with_backoff

logger = get_logger("webhooks")

# Maximum payload size to prevent accidentally sending large data
_MAX_PAYLOAD_SIZE = 64 * 1024  # 64 KiB
_REQUEST_TIMEOUT = 15  # seconds

def _resolve_and_validate_url(url: str) -> tuple[str, str]:
    """Resolve and validate a webhook target immediately before connecting.

    All returned DNS records must be globally routable. The selected address
    is used directly by the transport, preventing a subsequent DNS lookup from
    turning a validated hostname into a DNS-rebinding SSRF target.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if parsed.scheme != "https" or not hostname:
        raise ValueError("Webhook URL must be an HTTPS URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Webhook URLs must not contain user credentials")

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("Webhook URL contains an invalid port") from exc

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Cannot resolve hostname {hostname}: {exc}") from exc

        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for _family, _type, _proto, _canonname, sockaddr in infos:
            try:
                addresses.append(ipaddress.ip_address(sockaddr[0]))
            except ValueError as exc:
                raise ValueError(
                    f"Hostname {hostname} resolved to an invalid address"
                ) from exc
        if not addresses:
            raise ValueError(
                f"Hostname {hostname} resolved to no addresses"
            ) from None
    else:
        addresses = [address]

    for address in addresses:
        if _is_unsafe_webhook_address(address):
            raise ValueError(
                f"Webhook target resolves to non-public address {address}"
            )

    return url, str(addresses[0])


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that uses a validated IP but verifies the hostname."""

    def __init__(
        self,
        hostname: str,
        resolved_ip: str,
        *,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        self._resolved_ip = resolved_ip
        self._ssl_context = context
        super().__init__(hostname, port=port, timeout=timeout, context=context)

    def connect(self) -> None:
        """Connect to the pinned IP, retaining hostname SNI and TLS checks."""
        self.sock = socket.create_connection(
            (self._resolved_ip, self.port),
            self.timeout,
        )
        self.sock = self._ssl_context.wrap_socket(self.sock, server_hostname=self.host)


def _filter_actionable(findings: list[Any]) -> list[Any]:
    """Keep only FAIL/ERROR findings."""
    return actionable_findings(findings)


def _summary(findings: list[Any]) -> dict[str, Any]:
    """Build concise summary: count + top 5 control IDs."""
    filtered = _filter_actionable(findings)
    ids = [finding_control_id(f) for f in filtered]
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_ids: list[str] = []
    for cid in ids:
        if cid not in seen:
            seen.add(cid)
            unique_ids.append(cid)
    return {
        "total_failures": len(filtered),
        "top_controls": unique_ids[:5],
        "message": f"{len(filtered)} finding(s) failed. Top: {', '.join(unique_ids[:5])}",
    }


@retry_with_backoff(max_retries=3, base_delay=2.0)
def _post_json(url: str, payload: dict) -> None:
    """Post JSON payload to a URL with retry and size validation.

    Args:
        url: Target webhook URL (must be HTTPS).
        payload: JSON-serializable payload.

    Raises:
        ValueError: If payload exceeds size limit or URL is invalid.
        IOError: If the request fails after retries.
    """
    _url, resolved_ip = _resolve_and_validate_url(url)
    data = json.dumps(payload).encode()
    if len(data) > _MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload size ({len(data)} bytes) exceeds maximum ({_MAX_PAYLOAD_SIZE} bytes)"
        )

    parsed = urlparse(_url)
    hostname = parsed.hostname
    assert hostname is not None
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    context = ssl.create_default_context()
    conn = _PinnedHTTPSConnection(
        hostname, resolved_ip, port=port, timeout=_REQUEST_TIMEOUT, context=context
    )
    try:
        conn.putrequest("POST", path)
        conn.putheader("Host", hostname)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("User-Agent", "PagerWesi-Webhook/1.0")
        conn.putheader("Content-Length", str(len(data)))
        conn.putheader("Connection", "close")
        conn.endheaders()
        conn.send(data)

        response = conn.getresponse()
        if not 200 <= response.status < 300:
            raise OSError(f"HTTP Error {response.status}: {response.reason}")

    except (TimeoutError, socket.gaierror, OSError) as exc:
        raise OSError(f"Webhook request failed: {exc}") from exc
    finally:
        conn.close()

    logger.debug("Sending webhook to %s (pinned to %s, %d bytes)", url, resolved_ip, len(data))
    logger.info("Webhook delivered successfully to %s", url)


def send_slack(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Slack incoming webhook.

    Args:
        url: Slack webhook URL (must be HTTPS).
        findings: List of finding objects or dicts.
    """
    validated_url = validate_webhook_url(url)
    s = _summary(findings)
    payload = {
        "text": f":warning: PagerWesi Alert: {s['message']}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*PagerWesi Security Alert*\n{s['message']}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Failures:*\n{s['total_failures']}"},
                    {"type": "mrkdwn", "text": f"*Top Controls:*\n{', '.join(s['top_controls'])}"},
                ],
            },
        ],
    }
    _post_json(validated_url, payload)


def send_teams(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Microsoft Teams webhook.

    Args:
        url: Teams webhook URL (must be HTTPS).
        findings: List of finding objects or dicts.
    """
    validated_url = validate_webhook_url(url)
    s = _summary(findings)
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": f"PagerWesi Alert: {s['total_failures']} failures",
        "sections": [
            {
                "activityTitle": "PagerWesi Security Alert",
                "facts": [
                    {"name": "Total Failures", "value": str(s["total_failures"])},
                    {"name": "Top Controls", "value": ", ".join(s["top_controls"])},
                ],
                "markdown": True,
            }
        ],
    }
    _post_json(validated_url, payload)


def send_pagerduty(key: str, findings: list[Any]) -> None:
    """Trigger a PagerDuty event with findings summary.

    Args:
        key: PagerDuty routing/integration key.
        findings: List of finding objects or dicts.
    """
    if not key or len(key) < 10:
        raise ValueError("Invalid PagerDuty routing key")

    s = _summary(findings)
    severity = "critical" if s["total_failures"] > 5 else "error"
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": s["message"][:1024],  # PagerDuty limit
            "severity": severity,
            "source": "pagerwesi",
            "component": "security-audit",
            "custom_details": {
                "total_failures": s["total_failures"],
                "top_controls": s["top_controls"],
            },
        },
    }
    _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def notify(config: dict[str, str], findings: list[Any]) -> None:
    """Dispatch alerts based on config keys: slack_url, teams_url, pagerduty_key.

    Args:
        config: Notification configuration dict.
        findings: List of finding objects or dicts.
    """
    if not isinstance(config, dict):
        logger.error("Notification config must be a dict, got %s", type(config).__name__)
        return

    if not _filter_actionable(findings):
        logger.info("No actionable findings; skipping notifications")
        return

    errors: list[str] = []

    if config.get("slack_url"):
        try:
            send_slack(config["slack_url"], findings)
        except Exception as exc:
            errors.append(f"Slack: {exc}")
            logger.error("Slack notification failed: %s", exc)

    if config.get("teams_url"):
        try:
            send_teams(config["teams_url"], findings)
        except Exception as exc:
            errors.append(f"Teams: {exc}")
            logger.error("Teams notification failed: %s", exc)

    if config.get("pagerduty_key"):
        try:
            send_pagerduty(config["pagerduty_key"], findings)
        except Exception as exc:
            errors.append(f"PagerDuty: {exc}")
            logger.error("PagerDuty notification failed: %s", exc)

    if errors:
        logger.warning("Some notifications failed: %s", "; ".join(errors))
