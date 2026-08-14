# Security Policy

## Supported Versions

Security updates are provided for the latest stable release.

Reports affecting older versions are welcome, but fixes may be released only for the latest version. Users should upgrade before confirming whether an issue remains present.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately.

1. Go to `Security` → `Advisories` → `Report a vulnerability`.
2. If private vulnerability reporting is unavailable, open a public issue requesting a private security contact.
3. Do not include vulnerability details in that issue or disclose them through public issues, discussions, pull requests or other public channels.

Include when available:

* Affected package version and component
* PHP version and runtime environment
* Relevant extensions or dependencies
* Reproduction steps or a minimal proof of concept
* Exploitation requirements and potential impact
* Known workarounds or suggested remediation

## Response and Disclosure

The maintainers will make a best-effort attempt to:

* Acknowledge the report within five business days
* Validate the report and assess its severity
* Coordinate remediation and responsible disclosure
* Publish a fix, mitigation or security advisory when appropriate

Resolution timelines depend on severity, exploitability, complexity and maintainer availability. These targets are not a service-level agreement.

Please coordinate public disclosure with the maintainers so affected users have a reasonable opportunity to update or apply mitigations.

Confirmed reporters will receive credit unless they request anonymity.

## PHPForge Security Controls

This project uses [PHPForge](https://github.com/infocyph/PHPForge) to automate security and quality checks, including:

* Test and syntax validation
* Static and taint analysis
* Dependency vulnerability auditing
* Architecture validation
* Release-readiness checks
* Git hooks and CI enforcement

These controls help reduce security risk and prevent regressions, but they do not guarantee the absence of vulnerabilities or replace manual review and responsible reporting.
