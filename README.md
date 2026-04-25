# OTP

[![Security & Standards](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/OTP/actions/workflows/security-standards.yml)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/OTP?color=green\&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FOTP)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/OTP)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/OTP/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/OTP)
[![Documentation](https://img.shields.io/badge/Documentation-OTP-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/OTP/)

Standalone OTP and MFA primitives for PHP.

Supports:

- Generic OTP with PSR-6 storage
- TOTP (RFC6238)
- HOTP (RFC4226)
- OCRA (RFC6287)
- Recovery / backup codes
- `otpauth://` generation and parsing
- Replay-protection contracts and in-memory stores

## Requirements

- PHP 8.4+

## Version Compatibility

| OTP Library Line | PHP Requirement |
| --- | --- |
| `5.x` | `>=8.4` |
| `4.x` | `>=8.2` |
| `3.x` | `>=8.2` |
| `2.x` | `>=8.0` |
| `1.x` | `>=7.1` |

Use a matching major line when your runtime is pinned to an older PHP version.

## Project Policies

- Security reporting: [SECURITY.md](SECURITY.md)
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Installation

```bash
composer require infocyph/otp
```

## Highlights

- Base32 secret generation, normalization, and validation
- Safer provisioning URI and label handling
- SVG QR rendering plus raw payload/URI access
- Rich verification results where needed, simple bool APIs where preferred
- Configurable TOTP drift windows
- HOTP look-ahead resynchronization
- Replay protection contracts for TOTP, HOTP, and OCRA
- One-time recovery codes with hashed storage

## Quick Start

### TOTP

```php
<?php
use Infocyph\OTP\TOTP;

$secret = TOTP::generateSecret();

$totp = (new TOTP($secret))
    ->setAlgorithm('sha256');

$otp = $totp->getOTP();

$isValid = $totp->verify($otp);
```

Advanced verification with drift windows:

```php
<?php
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\ValueObjects\VerificationWindow;

$store = new InMemoryReplayStore();

$result = $totp->verifyWithWindow(
    $otp,
    timestamp: time(),
    window: new VerificationWindow(past: 1, future: 1),
    replayStore: $store,
    binding: 'user-42',
);

$result->matched;
$result->matchedTimestep;
$result->driftOffset;
$result->isExact();
$result->isDrifted();
$result->replayDetected;
```

Useful helpers:

```php
<?php
$totp->getCurrentTimeStep();
$totp->getRemainingSeconds();
$totp->getTimeStepFromTimestamp(1716532624);
```

### HOTP

```php
<?php
use Infocyph\OTP\HOTP;

$secret = HOTP::generateSecret();
$hotp = (new HOTP($secret))
    ->setCounter(3)
    ->setAlgorithm('sha256');

$otp = $hotp->getOTP(346);

$isValid = $hotp->verify($otp, 346);
```

Look-ahead verification with matched-counter result:

```php
<?php
use Infocyph\OTP\Stores\InMemoryReplayStore;

$result = $hotp->verifyWithResult(
    $otp,
    counter: 340,
    lookAhead: 10,
    replayStore: new InMemoryReplayStore(),
    binding: 'device-1',
);

$result->matched;
$result->matchedCounter;
$result->driftOffset;
```

### Generic OTP

Generic OTP is now string-based and uses a caller-provided PSR-6 cache pool.

```php
<?php
use Infocyph\OTP\OTP;
use Psr\Cache\CacheItemPoolInterface;

/** @var CacheItemPoolInterface $cachePool */
$otp = new OTP(
    digitCount: 6,
    validUpto: 60,
    retry: 3,
    hashAlgorithm: 'xxh128',
    cacheAdapter: $cachePool,
);

$code = $otp->generate('signup:alice@example.com');
$otp->verify('signup:alice@example.com', $code);
$otp->delete('signup:alice@example.com');
$otp->flush();
```

Notes:

- Codes are strings, not integers
- Leading zeroes are preserved
- Digit count must be between `4` and `10`

### OCRA

```php
<?php
use Infocyph\OTP\OCRA;

$ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', '12345678901234567890123456789012');

$ocra->setPin('1234');

$code = $ocra->generate('12345678', 0);
$isValid = $ocra->verify($code, '12345678', 0);
```

Replay-aware verification:

```php
<?php
use Infocyph\OTP\Stores\InMemoryReplayStore;

$result = $ocra->verifyWithResult(
    $code,
    challenge: '12345678',
    counter: 0,
    replayStore: new InMemoryReplayStore(),
    binding: 'user-42',
);
```

## Provisioning

### Generate `otpauth://` URIs

```php
<?php
$uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
```

### Render SVG QR

```php
<?php
$svg = $totp->getProvisioningUriQR('alice@example.com', 'Example App');
```

### Get enrollment payload

```php
<?php
$payload = $totp->getEnrollmentPayload(
    'alice@example.com',
    'Example App',
    withQrSvg: true,
);

$payload->secret;
$payload->uri;
$payload->qrPayload;
$payload->issuer;
$payload->label;
$payload->qrSvg;
```

### Parse existing `otpauth://` URIs

```php
<?php
use Infocyph\OTP\TOTP;

$parsed = TOTP::parseProvisioningUri($uri);

$parsed->type;
$parsed->secret;
$parsed->label;
$parsed->issuer;
$parsed->algorithm;
$parsed->digits;
$parsed->period;
$parsed->counter;
$parsed->ocraSuite;
```

## Replay Protection

The package ships with contracts plus an in-memory store for testing and lightweight use:

- `Infocyph\OTP\Contracts\ReplayStoreInterface`
- `Infocyph\OTP\Stores\InMemoryReplayStore`

Recommended usage:

- TOTP: store accepted timesteps per user/device binding
- HOTP: store last accepted counter
- OCRA: store used challenge/counter combinations where required

## Recovery Codes

```php
<?php
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

$codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());

$generated = $codes->generate(
    binding: 'user-42',
    count: 10,
    length: 10,
    groupSize: 4,
);

$generated->plainCodes;
$generated->totalGenerated;
$generated->remainingCount;
```

Consume a code:

```php
<?php
$result = $codes->consume('user-42', $generated->plainCodes[0]);

$result->consumed;
$result->reason;
$result->remainingCount;
$result->totalGenerated;
$result->lastUsedAt;
```

Notes:

- Recovery codes are stored hashed
- Generating a new set replaces the old set
- Display formatting is separate from storage hashing

## Secret Utilities

Base32 helpers live in `Infocyph\OTP\Support\SecretUtility`.

```php
<?php
use Infocyph\OTP\Support\SecretUtility;

$secret = SecretUtility::generate(64);
$normalized = SecretUtility::normalizeBase32('ab cd ef 234===');
$isValid = SecretUtility::isValidBase32($normalized);
```

## Result Objects

For richer flows, use the advanced APIs and inspect:

- `Infocyph\OTP\Result\VerificationResult`
- `Infocyph\OTP\Result\RecoveryCodeGenerationResult`
- `Infocyph\OTP\Result\RecoveryCodeConsumptionResult`

`VerificationResult` exposes:

- `matched`
- `reason`
- `matchedTimestep`
- `matchedCounter`
- `driftOffset`
- `replayDetected`
- `verifiedAt`

## Additional Helpers

- `Infocyph\OTP\Support\StepUp`
- `Infocyph\OTP\ValueObjects\DeviceEnrollment`

Example:

```php
<?php
use Infocyph\OTP\Support\StepUp;

$requiresFreshOtp = StepUp::requiresFreshOtp($verifiedAt, 300);
```

## Storage Guidance

- OTP secrets are reversible secrets. If your application needs to generate OTPs later, hashing alone is not enough.
- Recovery codes should usually be stored hashed.
- Replay state may live in cache or a database depending on durability needs.
- Generic OTP requires a PSR-6 cache pool implementation from the caller.

## OCRA Suite Notes

Example suite:

```text
OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1
```

Supported suite parts include:

- HMAC algorithms: `SHA1`, `SHA256`, `SHA512`
- Digits: `0`, `4`-`10`
- Challenge formats: numeric (`QNxx`), alphanumeric (`QAxx`), hexadecimal (`QHxx`)
- Optional counter, PIN, session, and time components

## References

- HOTP (RFC4226): https://tools.ietf.org/html/rfc4226
- TOTP (RFC6238): https://tools.ietf.org/html/rfc6238
- OCRA (RFC6287): https://tools.ietf.org/html/rfc6287
