# Infocyph OTP

[![Security & Standards](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/OTP?color=green\&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FOTP)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/OTP)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/OTP/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/OTP)
[![Documentation](https://img.shields.io/badge/Documentation-OTP-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/OTP/)

Framework-agnostic PHP 8.4 primitives for Generic OTP, HOTP (RFC 4226), TOTP
(RFC 6238), OCRA (RFC 6287), recovery codes, provisioning URIs, SVG QR codes,
secret rotation planning, and atomic replay boundaries.

## Requirements

- PHP `^8.4` on a 64-bit build
- `ext-ctype`
- Composer

```bash
composer require infocyph/otp
```

## TOTP quickstart

The default SHA-1/6-digit/30-second configuration has the broadest authenticator
compatibility.

```php
use Infocyph\OTP\TOTP;

$totp = new TOTP(TOTP::generateSecret());
$uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
$valid = $totp->verify($submittedCode);
```

For replay protection, a factor ID and an atomic store are both required:

```php
use Infocyph\OTP\Stores\InMemoryReplayStore;

$result = $totp->verifyWithWindow(
    $submittedCode,
    replayStore: new InMemoryReplayStore(), // examples/tests only
    factorId: 'totp-enrollment-v1',
);
```

`factorId` must identify one factor and secret generation, not merely a user.
Production stores must implement atomic conditional updates in shared durable
storage. The in-memory stores are process-local and are not production replay
protection.

## HOTP

```php
use Infocyph\OTP\HOTP;

$hotp = new HOTP(HOTP::generateSecret(), digits: 6, algorithm: 'sha1');
$code = $hotp->generate(counter: 10);
$result = $hotp->verifyWithResult($code, counter: 10);

$matched = $result->matchedCounter; // 10
$persist = $result->nextCounter;    // 11
```

Persist `nextCounter`, not `matchedCounter`. Supported counters are
`0..PHP_INT_MAX`; HOTP/TOTP use 6..9 digits and require at least 128-bit
decoded secrets.

## Generic OTP

```php
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Stores\InMemoryOtpStore;

$otp = new GenericOtp(
    store: new InMemoryOtpStore(), // examples/tests only
    key: $purposeSpecificApplicationKey,
    digits: 6,
    ttlSeconds: 300,
    maxAttempts: 3,
);

$code = $otp->generate('login-challenge-123');
$valid = $otp->verify('login-challenge-123', $submittedCode);
```

Issuing again for the same binding atomically replaces the previous code. A
successful verification consumes it. A mismatch decrements attempts without
changing the absolute expiration. HMAC-SHA-256 storage is mandatory and bound
to the challenge. Applications remain responsible for transport, resend
cooldowns, endpoint/account throttling, and anti-enumeration behavior.

## OCRA

OCRA operation inputs are explicit and suite-driven; an input is rejected when
the suite does not authenticate it.

```php
use Infocyph\OTP\OCRA;

$ocra = new OCRA(
    'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
    '12345678901234567890123456789012', // raw key for RFC integrations
);

$code = $ocra->generate(
    challenge: '12345678',
    counter: 4,
    pin: '1234',
);
```

Use `fromBase32()` for enrolled Base32 secrets. `generateMutual()` models
client/server challenge composition explicitly. Session input is actual UTF-8;
`sessionHex()` is an explicit integration helper. Time suites accept a bounded
`VerificationWindow`. Suites with `t=0` return uppercase hexadecimal; truncated
suites allow 4..9 digits. Challenge replay tokens are SHA-256 digests, and a
challenge replay TTL is optional; high-volume systems should choose a retention
policy that covers the complete acceptance window.

`otpauth://ocra` is a library/client convention, not an RFC-standardized
provisioning format. The consuming client must explicitly support it.

## Recovery codes

```php
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

$recovery = new RecoveryCodes(
    new InMemoryRecoveryCodeStore(), // examples/tests only
    $separateRecoveryHmacKey,
);
$batch = $recovery->generate('user-42'); // XXXX-XXXX-XXXX, about 60 bits
$result = $recovery->consume('user-42', $submittedCode);
```

The active batch is replaced on regeneration. Consumption and its returned
counts are one atomic mutation. Custom configurations must provide at least 40
bits of entropy. Submitted input is bounded before normalization.

## Security boundary

Correct OTP math is not a complete authentication workflow. Store factor
secrets encrypted, keep Generic OTP and recovery HMAC keys separate, use TLS,
apply rate limits, protect provisioning URIs/QR SVGs as secrets, rotate factor
IDs when secrets rotate, and implement atomic stores in Redis or a database.
See the security and storage guides for the required atomic semantics.


## Security

Do not disclose suspected vulnerabilities in a public issue, discussion or pull request. Review the
[security policy](SECURITY.md), then use [GitHub private vulnerability reporting](https://github.com/infocyph/OTP/security/advisories/new)
to contact the maintainers confidentially.

OTP is protected by [PHPForge](https://github.com/infocyph/PHPForge), an automated quality and security gate covering
tests, static and taint analysis, dependency auditing, architecture checks, and release readiness. Automated controls reduce
risk but do not replace responsible disclosure or manual review.

---

<div align="center">
  <sub><strong>Made with ❤️ for the PHP community</strong></sub><br />
  <sub><a href="LICENSE">MIT Licensed</a></sub><br />
  <a href="https://docs.infocyph.com/projects/OTP/en/latest/">Documentation</a> •
  <a href="SECURITY.md">Security</a> •
  <a href="CODE_OF_CONDUCT.md">Code of Conduct</a> •
  <a href="CONTRIBUTING.md">Contributing</a><br />
  <span title="Issue templates" aria-label="Issue templates">🗂️</span>
  <a href="https://github.com/infocyph/OTP/issues/new?template=bug_report.yml">Bug</a> •
  <a href="https://github.com/infocyph/OTP/issues/new?template=feature_request.yml">Feature</a> •
  <a href="https://github.com/infocyph/OTP/issues/new?template=docs_improvement.yml">Documentation</a> •
  <a href="https://github.com/infocyph/OTP/issues/new?template=question.yml">Question</a> •
  <a href="https://github.com/infocyph/OTP/issues/new?template=ci_failure.yml">CI failure</a><br />
  <span title="Pull request templates" aria-label="Pull request templates">🔀</span>
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=PULL_REQUEST_TEMPLATE.md">General</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=bug_fix.md">Bug fix</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=feature.md">Feature</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=refactor.md">Refactor</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=performance.md">Performance</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=security_reliability.md">Security &amp; reliability</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=documentation.md">Documentation</a> •
  <a href="https://github.com/infocyph/OTP/compare/main...HEAD?quick_pull=1&amp;template=maintenance.md">Maintenance</a>
</div>
