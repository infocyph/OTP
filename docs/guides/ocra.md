# OCRA

## Basic generation and verification

```php
use Infocyph\OTP\OCRA;

$ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', $sharedKey);
$ocra->setPin('1234');

$code = $ocra->generate('12345678', 0);
$ocra->verify($code, '12345678', 0);
```

## Optional suite inputs

Depending on the suite, you may need:

- `setPin()`
- `setSession()`
- `setTime()`

## Parsed suite details

```php
$suite = $ocra->getSuite();

$suite->algorithm;
$suite->digits;
$suite->counterEnabled;
$suite->challengeFormat;
$suite->challengeLength;
$suite->optionals;
```

## Replay protection

```php
use Infocyph\OTP\Stores\InMemoryReplayStore;

$result = $ocra->verifyWithResult(
    $code,
    challenge: '12345678',
    counter: 0,
    replayStore: new InMemoryReplayStore(),
    binding: 'user-42',
);
```
