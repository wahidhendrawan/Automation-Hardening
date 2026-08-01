# Changelog

## 0.10.1 - 2026-08-01

- Added `docs/architecture.md` documenting CLI structure, provider architecture,
  concurrent execution, and extension points.

## 0.10.0 - 2026-07-02

- Added structured logging with JSON output, auto-redaction of secrets, and log rotation
  (`--log-level`, `--log-json`, `--log-file`).
- Added rate limiting with token-bucket algorithm and exponential backoff retry for API calls.
- Added comprehensive input validation with SSRF protection on webhook URLs, path traversal
  prevention, and hostname/port validation.
- Added concurrent provider execution for the `all` command with error isolation.
- Enhanced secrets scanner: 12 detection patterns (AWS keys, GitHub/GitLab tokens, JWTs,
  database URLs, Azure/GCP credentials), configurable allowlist, severity per-pattern.
- Enhanced agent mode: state history rotation, resolved findings tracking, structured logging,
  minimum interval enforcement.
- Enhanced webhooks: retry logic with backoff, Slack block formatting, Teams MessageCard,
  PagerDuty severity escalation, payload size limits.
- Enhanced network scanner: concurrent endpoint scanning, input validation, rate limiting.
- Added 197 new tests (total: 214) covering secrets scanner, network scanner, webhooks,
  terraform plan, compliance, policy, remediation, input validator, rate limiter, concurrent
  runner, logging, agent, and dashboard generation.
- All new code passes `ruff check`, `mypy`, and achieves 67% coverage.

## 0.9.0 - 2026-06-19

- Completed the project rebrand to PagerWesi across the
  repository, CLI package metadata, documentation, GitHub Pages links, and container image names.
- Updated examples to use the `pagerwesi` CLI and PagerWesi-specific role/session naming.
- Added release notes for the rebrand release so downstream users have a clear migration target.

## 0.8.0 - 2026-06-18

- Added a reusable JSON Schema for machine-readable findings (`docs/finding.schema.json`).
- Added regression coverage to validate rendered JSON findings against the schema.
- Added `--watch-providers` for agent mode and preserved agent exit codes in the CLI.
- Changed agent provider failures to emit `AGENT-PROVIDER-001` error findings instead of being
  silently ignored.
- Fixed webhook, dashboard, and compliance exports to handle both `Finding` objects and serialized
  finding dictionaries consistently.
- Completed control metadata coverage for Docker, secrets, Terraform plan, and network/TLS
  scanners.
- Clarified that `pagerwesi all` runs the core cloud provider set only: AWS, Azure, GCP,
  and Kubernetes.
- Pinned the LocalStack integration image to avoid upstream `latest` license-token drift.
- Added community health files and updated project licensing metadata to GPL-3.0-or-later.
- Updated README, Quickstart, and GitHub Pages documentation for local scanners, finding schema,
  compliance evidence, dashboard generation, and agent mode.

## 0.7.0 - 2026-06-17

- Added webhook alerts for Slack, Microsoft Teams, and PagerDuty (`--notify`).
- Added pre-commit hook configuration for audit-on-commit workflows.
- Added compliance evidence export for SOC 2 and PCI DSS (`--export-compliance`).
- Added time-boxed exception/waiver management (`--exceptions`).
- Added Docker CIS Benchmark audit (daemon config, user namespaces, net=host, image tags).
- Added secrets detection scanner (AWS keys, private keys, hardcoded passwords).
- Added Terraform plan integration (security groups, public S3, IAM wildcards, encryption).
- Added GitHub App PR comment workflow for automatic security feedback.
- Added VS Code project settings and tasks.
- Added network/TLS scanner (TLS version, certificate validity, open ports).
- Added static HTML dashboard site generator (`--generate-dashboard`).
- Added agent/daemon mode with periodic audit and drift alerting (`--agent`).

## 0.6.0 - 2026-06-17

- Fixed Integration workflow to not block PR merges (`continue-on-error: true`).
- Added `k8s` to CI install extras for full coverage.
- Added ShellCheck and syntax validation for FreeBSD and Alpine scripts in CI.
- Added Bats tests for FreeBSD and Alpine scripts.
- Added K8s integration test workflow with kind cluster.
- Added Dependabot grouping for k8s, aws, azure, and gcp dependencies.
- Added SARIF upload to GitHub Security tab on main branch pushes.
- Added custom control authoring via YAML DSL (`--custom-controls`).
- Added remediation playbook generation (`--generate-playbook`) for Terraform and CloudFormation.
- Added scheduled drift detection workflow with automatic issue creation.
- Added HTML dashboard report format (`--format html`).

## 0.5.0 - 2026-06-17

- Added Kubernetes security controls: NetworkPolicy, RBAC, privileged pods, Pod Security Standards.
- Added FreeBSD audit/plan/apply script (PF firewall, SSH hardening, security patches).
- Added Alpine/container OS audit script (non-root user, package audit, read-only fs, shells).
- Added multi-cloud unified report: `pagerwesi all` runs all providers in one report.
- Added Azure/GCP plan mode (non-mutating) with plan manifest generation.
- Added `kubernetes` optional dependency group.
- Expanded control registry with K8S, FreeBSD, and Alpine controls.

## 0.4.0 - 2026-06-17

- Removed Node 20 warning by upgrading `actions/setup-python` to v6 across all workflows.
- Added AWS rollback handlers for EBS encryption by default, IAM Access Analyzer, and VPC Flow Logs.
- Added runtime JSON Schema validation for policy files with precise error paths (`jsonschema`).
- Added `pull_request` trigger with path filter to the LocalStack integration workflow.
- Enriched SARIF output with full descriptions, help URIs, NIST CSF / ISO 27001 / CIS framework
  tags, security-severity scores, markdown remediation guidance, and tool version metadata.
- Added non-mutating plan mode for Azure and GCP with plan manifest generation.
- Added `generate_control_docs.py` to produce `docs/controls.md` and `compliance-mapping.json`
  from the single-source control registry. CI enforces drift checks.
- Added GHCR container image publishing with provenance attestation in the release workflow.
- Updated GitHub Pages landing page to full English with container and plan mode sections.
- Updated README with container usage, expanded rollback boundaries, and Azure/GCP plan mode.

## 0.3.2 - 2026-06-17

- Added Node 24 transition flags across GitHub Actions workflows.
- Added optional scheduled/manual LocalStack integration workflow.
- Added policy schema and AWS policy settings for VPC Flow Logs apply mode.
- Added AWS apply support for EBS encryption by default and IAM Access Analyzer.
- Added AWS organization aggregate controls for CloudTrail, Config, GuardDuty, and Security Hub.
- Switched Azure subscription diagnostic settings to ARM REST lookup.
- Added provider permission examples and documentation version index.

## 0.3.1 - 2026-06-17

- Added a standalone quickstart guide and linked it from README and the promotional website.
- Added `pagerwesi policy validate --policy PATH`.
- Added AWS controls for EBS encryption by default, RDS storage encryption, VPC Flow Logs, and IAM
  Access Analyzer.
- Added Azure controls for Key Vault public access, SQL auditing, and diagnostic settings.
- Added GCP controls for service-account user-managed keys, Cloud KMS rotation, and audit logging.
- Added optional LocalStack S3 contract coverage and expanded Azure/GCP provider contract tests.

## 0.3.0 - 2026-06-15

- Added AWS rollback manifests for reversible S3 Public Access Block and encryption changes.
- Added explicit manual handling for irreversible S3 versioning transitions.
- Added validated YAML policy overrides for sensitive ports and resource exclusions.
- Added rollback and policy contract tests and a clean-wheel release smoke test.

## 0.2.1 - 2026-06-15

- Added deterministic plan manifests with before/after evidence for AWS remediations.
- Improved Azure and GCP public administrative-port detection for IPv6, lists, and ranges.
- Preserved the selected storage control ID when provider API access fails.
- Isolated AWS Organizations member-account failures so remaining accounts are still assessed.

## 0.2.0 - 2026-06-14

- Added audit/plan/apply execution modes and safe defaults.
- Added structured finding model with text, JSON, SARIF, and meaningful exit codes.
- Expanded AWS S3 coverage and deterministic remediation.
- Added authenticated Azure and GCP inventory adapters.
- Added safer Linux, macOS, and Windows baseline scripts.
- Added packaging, tests, linting, CI, CodeQL, dependency review, and Dependabot.
- Added multi-region AWS auditing, provider registry, provider tests, Linux smoke tests, and a
  provenance-attested release workflow.
- Added AWS Organizations account discovery and role assumption.
- Added Azure Storage, network, Defender, and activity log export controls.
- Added GCP Storage IAM, network firewall, and centralized logging controls.
- Added explicit apply-mode change manifests and informative compliance mappings.
- Raised minimum coverage to 80% and added Bats/Pester OS contract tests.
