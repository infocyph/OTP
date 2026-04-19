# Generic OTP

Generic OTP is useful when you want one-time codes without managing a dedicated OTP database table, while still keeping server-side verification state.

## PSR-6 cache requirement

```php
use Infocyph\OTP\OTP;

$otp = new OTP(
    digitCount: 6,
    validUpto: 60,
    retry: 3,
    hashAlgorithm: 'xxh128',
    cacheAdapter: $cachePool,
);
```

## Codes are strings

- generated codes are strings
- verification expects strings
- leading zeroes are preserved

## Basic flow

```php
$code = $otp->generate('signup:alice@example.com');
$otp->verify('signup:alice@example.com', $code);
$otp->delete('signup:alice@example.com');
```

## Retry semantics

```php
$otp->verify('signup:alice@example.com', $code, deleteIfFound: false);
```

When `deleteIfFound` is `false`, the record remains until it is verified, expires, or runs out of retries.
