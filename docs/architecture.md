# Architecture: PagerWesi

## Purpose

PagerWesi audits security baselines across operating systems, cloud providers (AWS, Azure, GCP), Kubernetes, Docker, Terraform plans, source trees, and network/TLS endpoints. Every entry point defaults to audit-only mode. Optional plan and apply modes support controlled remediation with rollback for supported AWS settings.

## Design & Components

### Package Layout (`cloud/`)

| Module | Responsibility |
|---|---|
| `main.py` | CLI entry (`pagerwesi ...`), argument parsing, provider dispatch |
| `core.py` | `Finding` dataclass, `Status`/`Severity` enums, renderers (text/JSON/SARIF), manifest generators |
| `control_registry.py` | Immutable `ControlMetadata` catalog with NIST CSF / ISO 27001 / CIS mappings |
| `providers/__init__.py` | Provider registry mapping names → module paths |
| `providers/aws/` | AWS baseline, organizations discovery, rollback, services |
| `aws_harden.py`, `azure_harden.py`, `gcp_harden.py`, `k8s_harden.py` | Per-provider `run_audit()` + `CONTROL_IDS` |
| `docker_cis.py`, `secrets_scanner.py`, `terraform_plan.py`, `network_scanner.py` | Local scanners requiring explicit scope |
| `policy.py` | JSON Schema policy loader/validator; exclusions and overrides |
| `custom_controls.py` | YAML-defined user controls without forking |
| `compliance.py` | Evidence export for SOC 2 / PCI-DSS frameworks |
| `remediation.py` | Playbook generator (Terraform / CloudFormation) from plan manifests |
| `html_report.py`, `dashboard_gen.py` | Self-contained HTML report + static dashboard site |
| `webhooks.py` | HTTPS-only notification with SSRF protection |
| `agent.py` | Daemon mode with state history + minimum interval enforcement |
| `concurrent_runner.py` | Thread-safe parallel provider execution with error isolation |
| `logging_config.py` | Structured JSON logging with auto-redaction of secrets |
| `input_validator.py`, `rate_limiter.py`, `finding_utils.py` | Cross-cutting utilities |

### OS Hardening Scripts

Standalone shell/PowerShell scripts live outside `cloud/`:
- `linux/harden.sh`, `macos/harden.sh`, `freebsd/harden.sh`, `alpine/harden.sh`
- `windows/harden.ps1`

Each supports `--mode audit|plan|apply`. Linux apply mode writes timestamped backups to `/var/backups/pagerwesi/` for rollback.

### Data Flow

```
CLI args → build_parser() → configure_logging()
  ↓
load_policy() → import provider module (importlib)
  ↓
module.run_audit(args) → list[Finding]
  ↓
[optional] custom controls, exceptions/waivers, notifications
  ↓
renderers: text | json | sarif | html
  ↓
[optional] change_manifest / plan_manifest / dashboard / compliance evidence
  ↓
exit_code(): 0 pass, 1 fail, 2 error
```

For the `all` command, `concurrent_runner.ConcurrentRunner` executes AWS/Azure/GCP/K8s providers in parallel with `max_workers=min(args.workers, 4)`. Failed providers are reported as `AGENT-PROVIDER-001` error findings rather than silently skipped.

### Finding Model

```python
@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    status: Status         # PASS | FAIL | ERROR | SKIP | MANUAL
    severity: Severity     # INFO | LOW | MEDIUM | HIGH | CRITICAL
    resource: str
    evidence: str
    remediation: str = ""
    benchmark: str = "Project baseline v1"
    changed: bool = False   # true in apply mode
    planned: bool = False   # true in plan mode
    before: object | None   # rollback restore value
    after: object | None    # planned/applied value
```

JSON output follows `docs/finding.schema.json`.

## Interfaces

### CLI

```bash
# Provider audit
pagerwesi aws --format text
pagerwesi aws --regions us-east-1,eu-west-1 --profile production
pagerwesi aws --organization-role PagerWesiAudit --external-id ...

# Plan + apply + rollback
pagerwesi aws --mode plan --plan-manifest reports/aws-plan.json
pagerwesi aws --mode apply --yes --change-manifest reports/aws-changes.json
pagerwesi aws --mode rollback --yes --rollback-manifest reports/aws-changes.json

# Multi-provider (parallel)
pagerwesi all --format sarif --output reports/unified.sarif

# Policy validation
pagerwesi policy validate --policy policy.example.yml

# Custom controls, exceptions, notifications
pagerwesi aws --custom-controls my-controls.yml
pagerwesi aws --exceptions exceptions.yml
pagerwesi aws --notify notify.yml

# Reports & dashboards
pagerwesi all --format html --output reports/dashboard.html
pagerwesi aws --generate-dashboard reports/site
pagerwesi aws --export-compliance soc2

# Agent mode
pagerwesi aws --agent --interval 300 --watch-providers aws,azure,gcp,k8s
```

Exit codes: `0` (all pass), `1` (failures present), `2` (errors or config issues).

## Local Development

```bash
# Install with dev extras
pip install -e '.[dev]'
# Provider extras
pip install -e '.[aws,azure,gcp,k8s]'

# Common Makefile targets
make test        # pytest with 60% coverage floor
make test-os     # bats + Pester tests for OS scripts
make lint        # ruff + compileall + shellcheck
make typecheck   # mypy on cloud/
make security    # pip-audit against requirements.lock
make docs        # regenerate control docs
```

CI (`.github/workflows/`) exercises Python 3.10/3.12, Ruff, pytest coverage, ShellCheck, Linux audit/plan smoke tests, PowerShell parsing, CodeQL, and LocalStack-backed integration tests.

## Extension Points

1. **Add a provider**: Register module path in `cloud/providers/__init__.py:PROVIDERS`, implement `run_audit(args)` and `CONTROL_IDS` in a new `cloud/<name>_harden.py`
2. **Add a control**: Add `ControlMetadata` in `control_registry.py`, implement check logic in the provider module returning `Finding` objects
3. **Custom controls without forking**: Provide YAML via `--custom-controls` (schema documented in `custom-controls.example.yml`)
4. **Policy overrides / exclusions**: Extend `policy.py` schema; new fields flow through `load_policy()`
5. **New output format**: Add renderer to `core.py` renderers dict and CLI `--format` choices
6. **Compliance framework**: Extend `compliance.py:export_evidence()` with a new framework key and mapping in `docs/compliance-mapping.json`
7. **New OS**: Add a `<os>/harden.sh` (or `.ps1`) script following the `--mode audit|plan|apply` convention

## Safety Model

- **Audit-only default** for every entry point
- `--mode apply` and `--mode rollback` require `--yes` acknowledgment
- Rollback restricted to AWS with matching change manifest
- Structured JSON logs auto-redact AWS keys, Bearer tokens, passwords
- Webhook URLs enforce HTTPS and reject private/loopback IPs (SSRF protection)
- Rate limiting with exponential backoff for cloud API calls
- Payload size limits on webhook notifications and manifest files
- Path traversal prevention with null byte detection
