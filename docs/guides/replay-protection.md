# Replay Protection

## Overview

Replay protection is intentionally pluggable.

Available contract:

- `Infocyph\OTP\Contracts\ReplayStoreInterface`

Included store:

- `Infocyph\OTP\Stores\InMemoryReplayStore`

## Recommended policy

### TOTP

- store the last accepted timestep per user or device binding
- reject the same timestep once accepted

### HOTP

- store the last accepted counter
- reject already-used counters
- persist any resynchronized counter once accepted

### OCRA

- reject reused challenge and counter combinations where the flow requires single use

## Example

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
