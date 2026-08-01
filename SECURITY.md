# Security Policy

PagerWesi audits sensitive infrastructure and performs controlled remediation, so security
vulnerabilities are handled with priority. Reports from the community are welcomed and treated
confidentially.

## Supported Versions

Security updates are provided for the latest minor release. Older releases may receive fixes at the
maintainers' discretion.

| Version   | Supported          |
| --------- | ------------------ |
| 0.10.x    | :white_check_mark: |
| < 0.10    | :x:                |

## Reporting a Vulnerability

Do not open a public issue, discussion, or pull request for a suspected vulnerability. Do not post
findings, exploit steps, or affected credentials in a public channel.

Report privately using one of the following:

1. **Preferred** — GitHub Private Vulnerability Reporting: open a report from the repository's
   Security tab (<https://github.com/wahidhendrawan/PagerWesi/security/advisories/new>).
2. Contact the repository owner privately through their verified GitHub profile if private
   reporting is unavailable.

Please include, when possible:

- Affected control, module, or workflow.
- Platform, PagerWesi version, and dependency versions used to reproduce.
- Minimal reproduction steps and expected vs. observed behavior.
- Impact assessment (privilege escalation, credential exposure, unsafe remediation, denial of
  service, data exposure, supply chain risk).
- Suggested mitigation or patch if available.

Do not include production credentials, real customer data, or sensitive posture reports.
Sanitize evidence before sharing.

## Response Expectations

- **Acknowledgement:** within 3 business days.
- **Initial assessment:** within 7 business days.
- **Fix or mitigation timeline:** depends on severity, typically 14 to 60 days.
- **Coordinated disclosure:** we work with reporters on a disclosure date once a fix is available.

Critical issues affecting active exploitation, remediation safety, or credential exposure are
prioritized above the standard timeline.

## Scope

In scope:

- Source code in this repository (`cloud/`, OS harden scripts, workflows, action).
- Published container image `ghcr.io/wahidhendrawan/pagerwesi`.
- Documented CLI, agent, and webhook behavior.

Out of scope:

- Vulnerabilities in third-party cloud services being audited (report to that provider).
- Findings that require the operator to run apply mode with intentionally over-privileged
  credentials.
- Denial-of-service tests against public infrastructure not owned by the reporter.

## Safe Harbor

Good-faith security research performed under this policy will not be pursued as a policy or
license violation. Follow responsible disclosure, do not access data beyond what is required to
demonstrate the issue, and do not degrade the service for other users.
