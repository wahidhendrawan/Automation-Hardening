# Contributing to PagerWesi

Thank you for considering a contribution. This document outlines the development workflow, testing
requirements, and submission guidelines.

## Development Setup

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/PagerWesi.git
   cd PagerWesi
   ```

2. **Create a virtual environment and install dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e '.[aws,azure,gcp,k8s,dev]'
   ```

3. **Verify your setup**:
   ```bash
   make test
   make lint
   make security
   ```

## Contribution Guidelines

### Branch Strategy

- Create a focused branch from `main` for each change.
- Use descriptive branch names: `fix/aws-s3-versioning`, `feat/gcp-kms-rotation`, `docs/quickstart-typo`.
- Keep changes independently reviewable. Avoid combining unrelated fixes in one PR.

### Code Quality

Before opening a pull request:

1. **Run tests and ensure they pass**:
   ```bash
   make test
   ```

2. **Run linters**:
   ```bash
   make lint
   ```

3. **Type-check Python code**:
   ```bash
   make typecheck
   ```

4. **Check for vulnerable dependencies**:
   ```bash
   make security
   ```

5. **Regenerate control documentation** if you added or modified controls:
   ```bash
   python scripts/generate_control_docs.py
   git diff docs/controls.md docs/compliance-mapping.json
   ```

### Testing Requirements

- Add tests for pass, fail, permission-error, and apply behavior when introducing new controls.
- Ensure existing tests continue to pass.
- Integration tests marked with `@pytest.mark.integration` are optional for PR validation but
  encouraged for AWS/cloud changes.
- OS script changes should include corresponding Bats or Pester tests.
- Target coverage: 60% minimum (current: ~81%). New modules should aim for 80%+.

### Control Changes

When proposing a new control or modifying an existing one:

- **Document the source** (CIS benchmark, NIST CSF, SOC2, PCI-DSS, or internal baseline).
- **Clarify applicability** (which platforms, resource types, regions).
- **Explain the check logic** and evidence.
- **Describe remediation** and whether it is deterministic, idempotent, and least-privilege.
- **Consider rollback implications** — can the change be safely reverted? Are there limitations?
- **Never include credentials, account identifiers, or real cloud reports** in test fixtures or
  documentation.

### Remediation Safety

New automatic remediation must meet strict criteria:

- **Explicit** — requires `--mode apply` and confirmation.
- **Deterministic** — identical inputs produce identical results.
- **Idempotent** — re-running does not cause unintended side effects.
- **Least-privilege** — requests only the permissions required.
- **Documented rollback** — clear instructions or automated rollback support.

Destructive or architecture-dependent remediation (e.g., rewriting bucket policies, deleting
resources, enabling paid services) should remain report-only with manual instructions.

### Pull Request Checklist

Your PR should:

- [ ] Have a clear title summarizing the change.
- [ ] Reference related issues if applicable (`Fixes #123`).
- [ ] Include tests for new functionality.
- [ ] Pass all CI checks (tests, linting, type-checking, security).
- [ ] Update documentation if behavior changes.
- [ ] Not include secrets, credentials, or production data.

### PR Template

When you open a pull request, the template will prompt you for:

- **Summary** — What control, platform, or behavioral change does this PR implement?
- **Safety** — Confirmation that audit mode is non-mutating and apply is explicit and documented.
- **Validation** — Checklist for `make test`, `make lint`, `make security`.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to
uphold this code. Report unacceptable behavior privately to the repository maintainers.

## Licensing

By contributing, you agree that your contributions will be licensed under the GPL-3.0 license. All
new files should include the appropriate license header if required by convention.

## Questions?

- Open a [Discussion](https://github.com/wahidhendrawan/PagerWesi/discussions) for general questions.
- Review existing [Issues](https://github.com/wahidhendrawan/PagerWesi/issues) and
  [Pull Requests](https://github.com/wahidhendrawan/PagerWesi/pulls) for context.
- Consult the [documentation](https://wahidhendrawan.github.io/PagerWesi/) for usage examples.

Thank you for helping improve PagerWesi!
