from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"TF-SEC-001", "TF-SEC-002", "TF-SEC-003", "TF-SEC-004"}

# Terraform plans can contain large state-derived values. Limit both the input
# file and resource list so a malformed or untrusted plan cannot exhaust memory
# or cause unbounded audit work.
_MAX_PLAN_BYTES = 50 * 1024 * 1024
_MAX_RESOURCE_CHANGES = 10_000


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _after(change: dict[str, Any]) -> dict[str, Any]:
    """Return a resource's post-change attributes only when structurally valid."""
    raw_change = change.get("change")
    if not isinstance(raw_change, dict):
        return {}
    after = raw_change.get("after")
    return after if isinstance(after, dict) else {}


def _check_open_cidr(change: dict[str, Any]) -> Finding | None:
    """TF-SEC-001: SG rule allowing 0.0.0.0/0."""
    rtype = change.get("type", "")
    if not isinstance(rtype, str) or (
        "security_group_rule" not in rtype and "security_group" not in rtype
    ):
        return None
    after = _after(change)
    cidrs = after.get("cidr_blocks", [])
    if isinstance(cidrs, list) and "0.0.0.0/0" in cidrs:
        return _finding(
            "TF-SEC-001",
            "Security group allows unrestricted ingress",
            Status.FAIL,
            Severity.HIGH,
            str(change.get("address", "unknown")),
            "cidr_blocks contains 0.0.0.0/0",
            "Restrict CIDR blocks to specific IP ranges.",
        )
    return None


def _check_public_s3(change: dict[str, Any]) -> Finding | None:
    """TF-SEC-002: Public S3 bucket."""
    rtype = change.get("type", "")
    if not isinstance(rtype, str) or "aws_s3_bucket" not in rtype:
        return None
    acl = _after(change).get("acl", "")
    if acl in ("public-read", "public-read-write"):
        return _finding(
            "TF-SEC-002",
            "S3 bucket with public ACL",
            Status.FAIL,
            Severity.CRITICAL,
            str(change.get("address", "unknown")),
            f"acl={acl}",
            "Set ACL to private and use bucket policies.",
        )
    return None


def _check_iam_star(change: dict[str, Any]) -> Finding | None:
    """TF-SEC-003: IAM policy with * actions."""
    rtype = change.get("type", "")
    if not isinstance(rtype, str) or "iam_policy" not in rtype:
        return None
    policy_str = _after(change).get("policy", "")
    if isinstance(policy_str, str) and '"Action":"*"' in policy_str.replace(
        " ", ""
    ).replace("'", '"'):
        return _finding(
            "TF-SEC-003",
            "IAM policy with wildcard actions",
            Status.FAIL,
            Severity.CRITICAL,
            str(change.get("address", "unknown")),
            "Action=* in policy document",
            "Restrict IAM actions to least privilege.",
        )
    return None


def _check_unencrypted(change: dict[str, Any]) -> Finding | None:
    """TF-SEC-004: Unencrypted resources."""
    after = _after(change)
    rtype = change.get("type", "")
    encrypt_fields = ["encrypted", "kms_key_id", "encryption_configuration"]
    if isinstance(rtype, str) and any(
        key in rtype for key in ("aws_ebs", "aws_rds", "aws_s3_bucket")
    ):
        has_encryption = any(after.get(field) for field in encrypt_fields)
        if not has_encryption:
            return _finding(
                "TF-SEC-004",
                "Resource lacks encryption configuration",
                Status.FAIL,
                Severity.HIGH,
                str(change.get("address", "unknown")),
                "No encryption field set",
                "Enable encryption at rest for this resource.",
            )
    return None


def _plan_error(plan_path: str, evidence: str) -> list[Finding]:
    return [
        _finding(
            "TF-SEC-001",
            "Terraform plan parse",
            Status.ERROR,
            Severity.HIGH,
            plan_path,
            evidence,
        )
    ]


def _load_plan(plan_path: str) -> tuple[dict[str, Any] | None, str | None]:
    """Read an untrusted Terraform plan with explicit resource bounds."""
    try:
        path = Path(plan_path)
        if path.stat().st_size > _MAX_PLAN_BYTES:
            return None, f"Plan exceeds maximum size of {_MAX_PLAN_BYTES} bytes"
        with path.open("rb") as plan_file:
            content = plan_file.read(_MAX_PLAN_BYTES + 1)
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if len(content) > _MAX_PLAN_BYTES:
        return None, f"Plan exceeds maximum size of {_MAX_PLAN_BYTES} bytes"

    try:
        plan = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if not isinstance(plan, dict):
        return None, "Terraform plan root must be a JSON object"
    return plan, None


def audit_plan(plan_path: str, args: Any) -> list[Finding]:
    plan, error = _load_plan(plan_path)
    if error:
        return _plan_error(plan_path, error)
    assert plan is not None

    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        return _plan_error(plan_path, "resource_changes must be a JSON array")
    if len(changes) > _MAX_RESOURCE_CHANGES:
        return _plan_error(
            plan_path,
            f"resource_changes exceeds maximum of {_MAX_RESOURCE_CHANGES} entries",
        )

    findings: list[Finding] = []
    checkers = [
        _check_open_cidr,
        _check_public_s3,
        _check_iam_star,
        _check_unencrypted,
    ]
    for index, change in enumerate(changes):
        if not isinstance(change, dict):
            return _plan_error(plan_path, f"resource_changes[{index}] must be an object")
        raw_change = change.get("change", {})
        if not isinstance(raw_change, dict):
            return _plan_error(
                plan_path,
                f"resource_changes[{index}].change must be an object",
            )
        actions = raw_change.get("actions", [])
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            return _plan_error(
                plan_path,
                f"resource_changes[{index}].change.actions must be an array",
            )
        if "create" not in actions and "update" not in actions:
            continue
        for checker in checkers:
            result = checker(change)
            if result:
                findings.append(result)
    return findings


def run_audit(args: Any) -> list[Finding]:
    plan_path = getattr(args, "plan", None) or getattr(args, "path", None)
    if not plan_path:
        return [
            _finding(
                "TF-SEC-001",
                "Terraform plan path required",
                Status.ERROR,
                Severity.HIGH,
                "terraform:plan",
                "No --plan or --path argument provided.",
                "Provide path to terraform plan JSON output.",
            )
        ]
    return audit_plan(str(plan_path), args)
