[![CI](https://github.com/wahidhendrawan/PagerWesi/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/PagerWesi/actions/workflows/ci.yml)

# PagerWesi 🛡️

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL-3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.10.0-green.svg)](https://github.com/wahidhendrawan/PagerWesi/releases)
[![CI](https://github.com/wahidhendrawan/PagerWesi/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/PagerWesi/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![CIS Compliance](https://img.shields.io/badge/CIS%20Compliance-SOC2%2FPCI--DSS-0052CC)](docs/)
[![HTML Reports](https://img.shields.io/badge/reports-HTML%20%7C%20JSON%20%7C%20Console-brightgreen)](cloud/html_report.py)
[![Pages](https://img.shields.io/badge/docs-🌐-orange.svg)](https://wahidhendrawan.github.io/PagerWesi/)
[![Last Commit](https://img.shields.io/github/last-commit/wahidhendrawan/PagerWesi)](https://github.com/wahidhendrawan/PagerWesi/commits/main)

Security baseline auditing and controlled remediation for operating systems, cloud providers,
Kubernetes, Docker, Terraform plans, source trees, and network/TLS endpoints. Every entry point
defaults to **audit-only** behavior. Review findings and test changes in a disposable environment
before using apply mode.

| Capability | Description |
|---|---|
| **HTML Reports** | Self-contained HTML dashboard with severity charts, finding tables, and download support |
| **CIS Compliance** | Score findings against SOC2, PCI-DSS, and custom control frameworks |
| **Multi-Provider** | AWS, Azure, GCP, Kubernetes, Docker, Terraform, OS baselines, network, TLS, secrets scanning |
| **Audit + Remediate** | Audit-only mode (safe) or controlled remediation with rollback support |

Promotional website and documentation are published at
**<https://wahidhendrawan.github.io/PagerWesi/>** via the included GitHub Pages workflow.
Source assets are in [docs/index.html](docs/index.html).

For a short setup path, start with [docs/quickstart.md](docs/quickstart.md). Provider permission
examples are in [docs/provider-permissions.md](docs/provider-permissions.md).

## What's New in v0.10.0

- **Structured Logging** — JSON and text log output with auto-redaction of secrets (AWS keys,
  Bearer tokens, passwords). Configurable via `--log-level`, `--log-json`, `--log-file` CLI flags
  or `PAGERWESI_LOG_LEVEL`/`PAGERWESI_LOG_JSON`/`PAGERWESI_LOG_FILE` environment variables.
- **Rate Limiting & Retry** — Exponential backoff retry for API calls with token-bucket rate
  limiting to prevent cloud provider throttling.
- **Input Validation & SSRF Protection** — All user inputs (endpoints, paths, webhook URLs) are
  validated. Webhook URLs enforce HTTPS-only and reject private/loopback IPs.
- **Concurrent Provider Execution** — The `all` command runs providers in parallel using
  thread-safe concurrent execution with error isolation.
- **Enhanced Secrets Scanner** — 12 detection patterns (up from 3) including GitHub/GitLab tokens,
  JWTs, database URLs, Azure connection strings, and GCP service account keys. Configurable
  allowlist to reduce false positives.
- **Agent Mode Improvements** — State history rotation, resolved findings tracking, structured
  logging, and minimum interval enforcement.
- **Comprehensive Test Suite** — 214 tests covering all modules with 67% code coverage.
  New test files for secrets scanner, network scanner, webhooks, terraform plan, compliance,
  policy, remediation, input validator, rate limiter, concurrent runner, logging, agent, and
  dashboard generation.

## Capabilities

| Target | Audit | Plan | Apply | Machine output |
|---|---:|---:|---:|---:|
| Linux | Yes | Yes | Yes | Text |
| macOS | Yes | Yes | Yes | Text |
| Windows | Yes | Yes | Yes | JSON |
| FreeBSD | Yes | Yes | Yes | Text |
| Alpine/Container | Yes | Yes | Limited | Text |
| AWS | Yes | Yes | Limited | Text, JSON, SARIF, HTML |
| Azure | Yes | Yes | — | Text, JSON, SARIF, HTML |
| GCP | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Kubernetes | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Docker | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Secrets | Yes | — | — | Text, JSON, SARIF, HTML |
| Terraform | Yes | — | — | Text, JSON, SARIF, HTML |
| Network/TLS | Yes | — | — | Text, JSON, SARIF, HTML |
| **All core cloud** | Yes | Yes | — | Text, JSON, SARIF, HTML |

Controls are project baselines inspired by common CIS recommendations. They are **not a claim of
CIS certification**. See [docs/controls.md](docs/controls.md) for scope and limitations.

## Cloud CLI

Python 3.10 or newer is required. Install only the providers you use:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[aws]'
pagerwesi aws --format text
```

Useful examples:

```bash
# Machine-readable report
pagerwesi aws --format json --output reports/aws.json

# One control and a named AWS profile
pagerwesi aws --control AWS-S3-004 --profile production

# Run regional controls across multiple AWS regions
pagerwesi aws --regions us-east-1,ap-southeast-1,eu-west-1

# Audit multiple AWS accounts represented by named profiles
pagerwesi aws --profiles production,security-audit --regions us-east-1,ap-southeast-1

# Discover active AWS Organization accounts and assume a standard audit role
pagerwesi aws --organization-role PagerWesiAudit \
  --external-id approved-external-id --regions us-east-1,ap-southeast-1

# Preview/apply deterministic AWS remediations
pagerwesi aws --mode plan \
  --plan-manifest reports/aws-plan.json
pagerwesi aws --mode apply --yes \
  --change-manifest reports/aws-changes.json

# Restore reversible settings from an apply change manifest
pagerwesi aws --mode rollback --yes \
  --rollback-manifest reports/aws-changes.json

# Azure/GCP plan mode (non-mutating)
pagerwesi azure --mode plan --plan-manifest reports/azure-plan.json
pagerwesi gcp --mode plan --plan-manifest reports/gcp-plan.json

# Apply validated policy overrides and documented resource exclusions
pagerwesi policy validate --policy policy.example.yml
pagerwesi aws --policy policy.example.yml

# SARIF for GitHub code scanning ingestion
pagerwesi aws --format sarif --output reports/aws.sarif

# Static dashboard and compliance evidence
pagerwesi aws --generate-dashboard reports/site
pagerwesi aws --export-compliance soc2 --output reports/aws.json
```

Exit codes are `0` for no failed/error findings, `1` for failed controls, and `2` for execution or
permission errors. AWS also checks root MFA, CloudTrail, Config, GuardDuty, Security Hub, default
security groups, EBS encryption by default, RDS encryption, VPC Flow Logs, IAM Access Analyzer, and
KMS rotation. Named profiles or AWS Organizations role assumption support
multi-account audits. Run regional controls in every governed region. Apply mode currently changes
supported S3 settings, EBS encryption by default, IAM Access Analyzer, and VPC Flow Logs when a
policy destination ARN is configured. It does not rewrite bucket policies, ACLs, broader logging
architecture, or paid security service plans.

Plan manifests contain the proposed before/after values and do not call mutation APIs. Azure and GCP
plan mode generates non-mutating plan manifests showing recommended changes. During AWS
Organizations audits, an inaccessible member account is reported without stopping assessment of the
remaining accounts.

Rollback restores account/bucket Public Access Block, default encryption, EBS encryption-by-default
changes, tool-created IAM Access Analyzers, and VPC Flow Logs from manifest values. AWS cannot
return a versioned bucket to its never-enabled state, so versioning rollback is reported as `MANUAL`
with a nonzero exit code. Review the manifest and use least-privilege credentials before confirming
rollback.

Policy files use `version: 1` and can override Azure/GCP administrative ports or exclude resources
with shell-style patterns. Exclusions are emitted as `SKIP` findings rather than silently omitted;
see [policy.example.yml](policy.example.yml). Policy validation uses JSON Schema and reports precise
error paths.

Azure audits Storage TLS and network rules, Key Vault public access, SQL auditing, NSG
administrative exposure, Defender plans, activity log exports, and diagnostic settings. GCP audits
public bucket IAM, uniform bucket access, service-account user-managed keys, KMS rotation, firewall
administrative exposure, logging sinks, and audit logging; Security Command Center remains an
organization-level manual control.

JSON findings follow the reusable schema in [docs/finding.schema.json](docs/finding.schema.json).
Use it to validate downstream ingestion for dashboards, SIEM pipelines, evidence stores, and
custom webhook processors.

## Container

A pre-built container image is published to GHCR on every version tag:

```bash
docker pull ghcr.io/wahidhendrawan/pagerwesi:latest

docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  ghcr.io/wahidhendrawan/pagerwesi:latest \
  aws --format sarif --output /dev/stdout
```

## Kubernetes

```bash
pip install -e '.[k8s]'
pagerwesi k8s --format text
pagerwesi k8s --mode plan --plan-manifest reports/k8s-plan.json
```

Checks NetworkPolicy coverage, cluster-admin RBAC bindings, privileged pods, and Pod Security
Standards enforcement. Connects via in-cluster config or `~/.kube/config`.

## Docker, Secrets, Terraform, and Network/TLS

Local scanners require explicit operator scope:

```bash
# Docker daemon/container posture
pagerwesi docker --format json --output reports/docker.json

# Source-tree secret detection; prefer a narrow path in CI
pagerwesi secrets --path ./src --format json --output reports/secrets.json

# Terraform plan review; generate JSON first
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
pagerwesi terraform --path tfplan.json --format json --output reports/terraform.json

# TLS and endpoint exposure checks
pagerwesi network --endpoints example.com:443,api.example.com:443 \
  --format json --output reports/network.json
```

## Core Cloud Unified Report

```bash
pip install -e '.[aws,azure,gcp,k8s]'
pagerwesi all --format json --output reports/unified.json
pagerwesi all --format sarif --output reports/unified.sarif
```

Runs the core cloud providers (`aws`, `azure`, `gcp`, and `k8s`) sequentially and combines findings
into a single report. Unavailable providers are skipped gracefully. Local scanners are explicit
commands because they require an operator-selected path or endpoint scope:

```bash
pagerwesi docker --format json --output reports/docker.json
pagerwesi secrets --path . --format json --output reports/secrets.json
pagerwesi terraform --path tfplan.json --format json --output reports/terraform.json
pagerwesi network --endpoints example.com:443 --format json --output reports/network.json
```

## FreeBSD

```bash
sudo sh freebsd/harden.sh --mode audit
sudo sh freebsd/harden.sh --mode plan
sudo sh freebsd/harden.sh --mode apply
```

Checks PF firewall, SSH root login, empty passwords, and security patches.

## Alpine / Container OS

```bash
sh alpine/harden.sh --mode audit
sh alpine/harden.sh --mode plan
sh alpine/harden.sh --mode apply
```

Checks non-root user, vulnerable packages, read-only root filesystem, and unnecessary shells.

## Operating Systems

Audit is always the default:

```bash
sudo bash linux/harden.sh --mode audit
sudo bash linux/harden.sh --mode plan
sudo bash linux/harden.sh --mode apply

sudo bash macos/harden.sh --mode audit
sudo bash macos/harden.sh --mode plan
sudo bash macos/harden.sh --mode apply

powershell -File windows/harden.ps1 -Mode Audit -OutputPath report.json
powershell -File windows/harden.ps1 -Mode Plan
powershell -File windows/harden.ps1 -Mode Apply
```

Linux apply mode creates a timestamped SSH backup under
`/var/backups/pagerwesi/`. Restore it with:

```bash
sudo bash linux/harden.sh --rollback /var/backups/pagerwesi/TIMESTAMP
```

Linux firewall apply mode permits the service in `ALLOW_SSH` before enabling the firewall. For a
nonstandard service or rule, set it explicitly and verify the plan first:

```bash
sudo ALLOW_SSH=OpenSSH bash linux/harden.sh --mode plan
```

## Custom Controls

Define your own controls in YAML without forking:

```yaml
# my-controls.yml
version: 1
controls:
  - id: CUSTOM-DNS-001
    title: DNS resolver uses internal nameservers
    check: "grep -q 'nameserver 10\\.' /etc/resolv.conf"
    severity: medium
    remediation: "Configure internal DNS in /etc/resolv.conf"
```

```bash
pagerwesi aws --custom-controls my-controls.yml
```

## Remediation Playbooks

Generate Terraform or CloudFormation from plan manifests:

```bash
pagerwesi aws --generate-playbook reports/plan.json --output remediation.tf
pagerwesi aws --generate-playbook reports/plan.json \
  --playbook-format cloudformation --output remediation.yml
```

## HTML Dashboard

```bash
pagerwesi all --format html --output reports/dashboard.html
```

Produces a self-contained HTML file with pass/fail/error statistics and a findings table for the
core cloud provider set. Run explicit local scanners separately when you need Docker, secrets,
Terraform plan, or network/TLS evidence.

## Drift Detection

A scheduled workflow runs daily, audits the core cloud provider set, and creates a GitHub Issue if
controls are failing. See `.github/workflows/drift-detection.yml`.

## Agent Mode

Agent mode runs periodic audits and can send webhook notifications when new failures or provider
errors appear:

```bash
pagerwesi aws --agent --interval 300 --watch-providers aws,azure,gcp,k8s \
  --notify notify.yml
```

Provider runtime failures are emitted as `AGENT-PROVIDER-001` error findings instead of being
silently ignored.

## Secure Coding & Logging

PagerWesi v0.10 integrates defense-in-depth secure coding practices:

```bash
# Structured JSON logging (SIEM-ready)
pagerwesi aws --log-level debug --log-json --log-file audit.log

# Environment variable configuration
export PAGERWESI_LOG_LEVEL=INFO
export PAGERWESI_LOG_JSON=true
export PAGERWESI_LOG_FILE=/var/log/pagerwesi/audit.log
```

Security features include:
- **Secret auto-redaction** in all log output (AWS keys, passwords, Bearer tokens)
- **SSRF protection** on webhook URLs (rejects private IPs, enforces HTTPS)
- **Input validation** on all CLI inputs (paths, endpoints, hostnames, ports)
- **Rate limiting** for cloud API calls with exponential backoff retry
- **Payload size limits** on webhook notifications and manifest files
- **Path traversal prevention** with null byte detection and symlink controls
- **HTML entity escaping** in dashboard reports (XSS prevention)

## Development

```bash
pip install -e '.[dev]'
make test
make lint
make security
make test-os
make docs
```

CI checks Python 3.10/3.12, Ruff, pytest coverage, ShellCheck, Linux audit/plan smoke tests,
PowerShell parsing, CodeQL, pull-request dependency review, and integration tests with LocalStack.
Version tags build a GitHub Release with Python artifacts, checksums, CycloneDX SBOM, container
image, and provenance attestation. See [CONTRIBUTING.md](CONTRIBUTING.md).

Control relationships to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, and CIS benchmark families are
documented in [docs/compliance-mapping.json](docs/compliance-mapping.json). These mappings are
informative and do not constitute certification.

## Safety

- Use least-privilege read-only cloud credentials for audit mode.
- Capture backups and test apply mode in a VM or disposable account first.
- Review network access before enabling a host firewall remotely.
- Use an approved recovery-key escrow process before enabling FileVault or BitLocker.
- Treat generated reports as sensitive because they contain resource identifiers and posture data.

This project is provided under the GPL-3.0 license without warranty.
