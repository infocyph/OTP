# Security Policy

## Supported Versions

The project currently supports security updates for the latest release.

## Reporting a Vulnerability

Please report vulnerabilities privately.

1. Use GitHub private vulnerability reporting for this repository (`Security` -> `Advisories` -> `Report a vulnerability`).
2. If private reporting is unavailable, contact maintainers through a private channel.
3. Do not open a public issue for security vulnerabilities.

Please include:

- Affected package version(s)
- PHP version and runtime environment
- Reproduction steps or proof of concept
- Impact assessment (confidentiality/integrity/availability)
- Any known workaround

## Response Process

- Initial acknowledgment: best effort, typically within a few days
- Triage: best effort, based on maintainer availability
- Fix and release timeline depends on severity and exploitability

If a report is accepted, a patched release will be prepared and published. Credit will be provided unless you request otherwise.

## Protected by PHPForge

This project is protected by [PHPForge](https://github.com/infocyph/PHPForge), an automated quality and security tooling layer for Infocyph PHP projects.

PHPForge helps keep the project reliable by running checks for:

- Code style and standards
- Tests and syntax validation
- Static analysis and type safety
- Security and taint analysis
- Dependency vulnerability audit
- Architecture boundary validation
- Duplicate-code detection
- API snapshot and comment-policy checks
- Refactor safety checks
- Benchmark and release-readiness checks
- Git hooks and CI workflow protection

These automated gates strengthen code quality, reduce security risk and help prevent regressions before merge or release.
