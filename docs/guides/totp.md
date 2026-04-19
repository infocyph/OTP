# TOTP

## Creating an instance

```php
use Infocyph\OTP\TOTP;

$totp = new TOTP($secret, digitCount: 6, period: 30);
```

## Basic verification

```php
$totp->verify($otp, timestamp: time(), pastWindows: 1, futureWindows: 1);
```

## Rich verification results

```php
use Infocyph\OTP\ValueObjects\VerificationWindow;

$result = $totp->verifyWithWindow(
    $otp,
    timestamp: time(),
    window: new VerificationWindow(past: 1, future: 0),
);

$result->matched;
$result->matchedTimestep;
$result->driftOffset;
$result->isExact();
$result->isDrifted();
```

## Time helpers

```php
$totp->getCurrentTimeStep();
$totp->getRemainingSeconds();
$totp->getTimeStepFromTimestamp(1716532624);
```

## Replay protection

```php
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\ValueObjects\VerificationWindow;

$result = $totp->verifyWithWindow(
    $otp,
    window: new VerificationWindow(past: 1, future: 1),
    replayStore: new InMemoryReplayStore(),
    binding: 'user-42',
);
```

## Secret rotation helper

```php
$rotation = $totp->rotateSecret($newSecret, gracePeriodInSeconds: 3600);

$rotation['current'];
$rotation['next'];
$rotation['overlapUntil'];
```
