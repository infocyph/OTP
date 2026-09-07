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
- `ext-sodium`
- CacheLayer `^3.3`
- Composer

```bash
composer require infocyph/otp
```

Passkey support is optional. Install its upstream WebAuthn implementation only
when needed:

```bash
composer require web-auth/webauthn-lib:^5.3
```

OTP lists that package under Composer `suggest` and installs it in `require-dev`
for its own tests/static analysis, so HOTP/TOTP-only consumers do not inherit the
WebAuthn/CBOR/PKI/Symfony dependency graph.

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
configured CacheLayer backend with no TTL.

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
machine. The CacheLayer backend must therefore expose a coordinated lock even if
it also supports native atomics.

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
    '12345678901234567890123456789012',
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
suites allow 4..9 digits.

Counter OCRA replay state is monotonic and has no TTL. When CacheLayer replay
protection is enabled for a non-counter suite, a positive `replayTtl` is
mandatory; for time suites it must cover the complete accepted time window.
`otpauth://ocra` is a library/client convention, not an RFC-standardized
provisioning format, so the consuming client must explicitly support it.

## AOTP

AOTP uses Ed25519 challenge signatures so the verifier can authenticate a client
without holding a shared signing secret.

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

The signed payload binds challenge ID, 256-bit nonce, audience, context,
issuance, and expiration. Cache state is keyed by the complete canonical
challenge, so changing context or expiry cannot reuse an issued reservation.
Successful verification atomically transitions the reservation from unconsumed
to consumed; a concurrent duplicate is reported as replay.

AOTP uses CacheLayer native atomics when available and the coordinated lock
fallback otherwise. The client must independently enforce the expected audience
before signing. Generic AOTP integration should not be advertised as phishing
resistant unless the application also enforces verifier/context binding end to
end. See [AOTP](docs/guides/aotp.rst).

## GridOTP

GridOTP is a human-computable dynamic-grid challenge. The enrolled secret uses a
32-symbol alphabet and the challenge asks for 6..10 secret positions. Every
challenge regenerates a balanced many-to-one mapping from secret symbols to
response digits.

```php
use Infocyph\OTP\GridOTP;

$secret = GridOTP::generateSecret();
$gridOtp = new GridOTP($stateCache, $secret);
$challenge = $gridOtp->issue('user-42:grid:v1');
$response = GridOTP::respond($challenge, $secret);
$result = $gridOtp->verifyWithResult('user-42:grid:v1', $challenge, $response);
```

The user never submits the enrolled secret directly. A captured response cannot
be replayed against a new grid. The many-to-one mapping also prevents one full
visual observation from uniquely revealing every challenged secret symbol, but
repeated observations can intersect candidate sets and recover the secret.
GridOTP therefore reduces direct password/keylogger exposure; it is **not**
shoulder-surfing proof and remains one knowledge factor rather than MFA.

GridOTP is lock-based because attempts, expiry, challenge-integrity state, and
consumption are one multi-field transition. See [GridOTP](docs/guides/grid-otp.rst).

## MobileOTP

`MobileOTP` is strict compatibility for the established Mobile-OTP/mOTP protocol:
a 10-second timestep, a 16-hex-character Init-Secret, a four-digit PIN, and the
first six lowercase hexadecimal characters of the legacy MD5 calculation.

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
    factorId: 'user-42:mobile:v1',
);
```

The default verification window is zero. Compatibility windows may be widened
explicitly up to the historical ±3-minute ceiling (18 ten-second steps per
direction). Replay-aware verification advances the greatest accepted timestep
through CacheLayer atomics/lock fallback just like TOTP.

MD5 is used **only because it is part of the legacy Mobile-OTP wire algorithm**.
Do not choose MobileOTP for a new authentication design; prefer TOTP, AOTP, or
Passkey. See [MobileOTP](docs/guides/mobile-otp.rst).

## Passkey / WebAuthn

Passkey support is a ceremony/state wrapper around `web-auth/webauthn-lib`, not a
custom WebAuthn implementation. The authenticator keeps the private key; the
application persists the upstream `CredentialRecord` returned by successful
registration/authentication.

```php
use Infocyph\OTP\Passkey;

$passkey = new Passkey(
    cache: $stateCache,
    rpId: 'example.com',
    rpName: 'Example',
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

Registration requires a discoverable credential and user verification, with
attestation conveyance `none`. Authentication supports both account-bound
`allowCredentials` and discoverable/usernameless flows. On every successful
authentication, persist the **updated** `credentialRecordJson`; WebAuthn counter,
backup, and UV state may have changed.

Full creation/request options are stored server-side under a random 128-bit
ceremony ID. A successful ceremony remains marked consumed until its original
expiry, so concurrent duplicates are reported as replay. Durable credential
records are application-owned database state, never CacheLayer state. See
[Passkey](docs/guides/passkey.rst).

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

The active batch is replaced on regeneration. Consumption and its returned
counts are one atomic mutation. Custom configurations must provide at least 40
bits of entropy. Submitted input is bounded before normalization. Production
applications should implement `RecoveryCodeStoreInterface` with authoritative,
durable, atomic replacement and consumption.

## Security boundary

Correct OTP math is not a complete authentication workflow. Store
HOTP/TOTP/OCRA, GridOTP, and MobileOTP secrets encrypted; protect AOTP private
keys on the client; persist passkey CredentialRecords in an authoritative durable
store; keep Generic OTP and recovery HMAC keys separate; use TLS; apply rate
limits; protect provisioning material; and rotate factor IDs when secrets, keys,
or moving-factor generations rotate.

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
