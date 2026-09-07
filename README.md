# Infocyph OTP

[![Security & Standards](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/OTP?color=green\&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FOTP)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/OTP)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/OTP/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/OTP)
[![Documentation](https://img.shields.io/badge/Documentation-OTP-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/OTP/)

Framework-agnostic PHP 8.4 primitives for Generic OTP, HOTP (RFC 4226), TOTP
(RFC 6238), OCRA (RFC 6287), AOTP asymmetric challenge-response, GridOTP dynamic
grid authentication, legacy Mobile-OTP/mOTP, optional WebAuthn passkeys,
recovery codes, provisioning URIs, SVG QR codes, secret rotation planning, and
CacheLayer-backed replay boundaries.

AOTP and GridOTP are Infocyph-defined protocol primitives. MobileOTP implements
the established legacy mOTP wire calculation. Passkey delegates WebAuthn
cryptography and ceremony validation to `web-auth/webauthn-lib`. None of these
four uses `otpauth://` provisioning.

## Requirements

- PHP `^8.4` on a 64-bit build
- `ext-ctype`
- CacheLayer `^3.3`
- Composer

```bash
composer require infocyph/otp
```

### Optional integrations

AOTP requires `ext-sodium` for Ed25519. OTP keeps sodium under Composer
`require-dev` + `suggest`, so applications that do not use AOTP do not need it.
Use `AOTP::isAvailable()` before exposing AOTP when the production PHP image may
not include sodium.

Passkey/WebAuthn requires the upstream WebAuthn implementation:

```bash
composer require web-auth/webauthn-lib:^5.3
```

OTP keeps `web-auth/webauthn-lib` under `require-dev` + `suggest` as well.
`Passkey::isAvailable()` reports whether it is loaded. OTP's Passkey integration
does **not** require `ext-sodium`.

## TOTP quickstart

The default SHA-1/6-digit/30-second configuration has the broadest authenticator
compatibility.

```php
use Infocyph\OTP\TOTP;

$totp = new TOTP(TOTP::generateSecret());
$uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
$valid = $totp->verify($submittedCode);
```

The boolean path is stateless. For single-use acceptance, pass a configured
CacheLayer authentication-state cache and a generation-specific factor ID:

```php
$result = $totp->verifyWithWindow(
    otp: $submittedCode,
    cache: $stateCache,
    factorId: 'user-42:totp:secret-v1',
);
```

`$stateCache` must be fail-closed, payload-integrity protected, and authoritative.
CacheLayer 3.3 native atomics are preferred when the backend exposes them;
otherwise TOTP/HOTP/OCRA use the cache's coordinated lock fallback. A selected
atomic backend failure propagates and is never retried through locks. `factorId`
must identify one factor and secret/moving-factor generation, not merely a user.
See [storage](docs/guides/storage.rst) and
[replay protection](docs/guides/replay-protection.rst) before production use.

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
decoded secrets. Replay-aware HOTP stores the greatest accepted counter in the
configured CacheLayer backend with no TTL. See [HOTP](docs/guides/hotp.rst).

## Generic OTP

```php
use Infocyph\OTP\GenericOtp;

$otp = new GenericOtp(
    cache: $stateCache,
    key: $purposeSpecificApplicationKey,
    digits: 6,
    ttlSeconds: 300,
    maxAttempts: 3,
);

$code = $otp->generate('login-challenge-123');
$valid = $otp->verify('login-challenge-123', $submittedCode);
```

Generic OTP deliberately remains lock-based because issue/replace, consumption,
failed-attempt decrement, expiry, and deletion form one multi-field state
machine. A successful verification consumes the challenge; a mismatch decrements
attempts without extending expiry. See [Generic OTP](docs/guides/generic-otp.rst).

## OCRA

OCRA operation inputs are explicit and suite-driven; an input is rejected when
the suite does not authenticate it.

```php
use Infocyph\OTP\OCRA;

$ocra = new OCRA(
    'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
    '12345678901234567890123456789012',
);

$code = $ocra->generate(
    challenge: '12345678',
    counter: 4,
    pin: '1234',
);
```

Use `fromBase32()` for enrolled Base32 secrets. Counter OCRA replay state is
monotonic; non-counter replay protection requires an explicit replay TTL.
`otpauth://ocra` is a library/client convention rather than an RFC-standardized
provisioning format. See [OCRA](docs/guides/ocra.rst).

## AOTP

AOTP is an optional Ed25519 challenge-response primitive. The verifier keeps the
public key while the client/device keeps the private key.

```php
use Infocyph\OTP\AOTP;

$keys = AOTP::generateKeyPair();
$aotp = new AOTP($keys->publicKey, 'login.example.com');
$challenge = $aotp->issue($stateCache, 'user-42:aotp:key-v1', 'login');
$response = AOTP::respond($keys->privateKey, $challenge, 'login.example.com');
$result = $aotp->verifyWithResult(
    $stateCache,
    'user-42:aotp:key-v1',
    $challenge,
    $response,
);
```

The signed payload binds challenge ID, nonce, audience, context, issuance, and
expiration. Successful verification atomically consumes the issued reservation;
a concurrent duplicate is replay. The client must independently enforce the
expected audience. AOTP requires `ext-sodium`. See [AOTP](docs/guides/aotp.rst)
for the complete client/server flow.

## GridOTP

GridOTP is a human-computable dynamic-grid knowledge factor. Every challenge
regenerates a balanced mapping and requests 6..10 positions from the enrolled
secret.

```php
use Infocyph\OTP\GridOTP;

$secret = GridOTP::generateSecret();
$gridOtp = new GridOTP($stateCache, $secret);
$challenge = $gridOtp->issue('user-42:grid:secret-v1');
$response = GridOTP::respond($challenge, $secret);
$result = $gridOtp->verifyWithResult(
    'user-42:grid:secret-v1',
    $challenge,
    $response,
);
```

The enrolled secret is not submitted during authentication and a captured
response cannot be replayed against a new grid. Repeated full observations can
still recover secret symbols, so GridOTP is not shoulder-surfing proof and is
one knowledge factor rather than MFA. See [GridOTP](docs/guides/grid-otp.rst).

## MobileOTP

`MobileOTP` provides strict compatibility with legacy Mobile-OTP/mOTP: a
10-second timestep, 16-hex-character Init-Secret, four-digit PIN, and first six
lowercase hexadecimal characters of the protocol's MD5 calculation.

```php
use Infocyph\OTP\MobileOTP;

$mobile = new MobileOTP(
    secret: MobileOTP::generateSecret(),
    pin: '5555',
);

$otp = $mobile->generate();
$result = $mobile->verifyWithWindow(
    otp: $submittedOtp,
    cache: $stateCache,
    factorId: 'user-42:mobile:secret-v1',
);
```

The default window is zero; legacy tolerance can be configured up to 18
10-second steps per direction. MD5 is used only because it is part of the legacy
wire algorithm. Prefer TOTP or Passkey for new deployments. See
[MobileOTP](docs/guides/mobile-otp.rst).

## Passkey / WebAuthn

Passkey is an optional ceremony/state wrapper around `web-auth/webauthn-lib`.
The authenticator owns the private key and the application persists the upstream
`CredentialRecord`.

```php
use Infocyph\OTP\Passkey;

$passkey = new Passkey(
    cache: $stateCache,
    rpId: 'example.com',
    allowedOrigins: ['https://example.com'],
);

$ceremony = $passkey->beginRegistration(
    binding: 'user-42:passkey:registration',
    userHandle: $opaqueStableUserHandle,
    username: 'alice@example.com',
    displayName: 'Alice',
);

$result = $passkey->finishRegistration(
    binding: 'user-42:passkey:registration',
    ceremonyId: $submittedCeremonyId,
    credentialJson: $browserCredentialJson,
);
```

There is no `rpName` constructor argument; OTP uses the RP ID as the serialized
RP display name. Registration requests discoverable credentials and user
verification. Authentication supports account-bound and discoverable flows.
Persist the updated `credentialRecordJson` after every successful assertion.
Passkey does not require `ext-sodium` from OTP. See
[Passkey/WebAuthn](docs/guides/passkey.rst) for complete browser and server code.

## Recovery codes

```php
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

$recovery = new RecoveryCodes(
    new InMemoryRecoveryCodeStore(),
    $separateRecoveryHmacKey,
);
$batch = $recovery->generate('user-42');
$result = $recovery->consume('user-42', $submittedCode);
```

Regeneration replaces the entire active batch and consumption is atomic and
single-use. Production applications should implement
`RecoveryCodeStoreInterface` with authoritative durable atomic persistence. See
[Recovery codes](docs/guides/recovery-codes.rst).

## Security boundary

Correct OTP math is not a complete authentication workflow. Store
HOTP/TOTP/OCRA, GridOTP, and MobileOTP secrets encrypted; protect AOTP private
keys on the client; persist passkey `CredentialRecord` data in an authoritative
durable store; keep Generic OTP and recovery HMAC keys separate; use TLS; apply
rate limits; protect provisioning material; and rotate factor IDs when secrets,
keys, or moving-factor generations rotate.

For Generic OTP, GridOTP, AOTP, Passkey ceremonies, MobileOTP replay, and
replay-aware HOTP/TOTP/OCRA, configure one shared, fail-closed,
payload-integrity protected, authoritative CacheLayer backend. Generic OTP,
GridOTP, and Passkey ceremonies additionally require a coordinated lock because
their state transitions are multi-field. Recovery-code and passkey credential
persistence remain application-owned. Backend/configuration failures propagate
and fail closed. See [security](docs/guides/security.rst) and
[storage](docs/guides/storage.rst).

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
