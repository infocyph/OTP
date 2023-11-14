# OTP

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/7470c9de3a5848f982b77f005945b04f)](https://app.codacy.com/gh/abmmhasan/OTP/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/abmmhasan/otp)
![Packagist Downloads (custom server)](https://img.shields.io/packagist/dt/abmmhasan/otp?color=green&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Fabmmhasan%2Fotp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/abmmhasan/otp)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/abmmhasan/otp/php)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/abmmhasan/otp)

Simple but Secure Generic OTP, TOTP (RFC6238), HOTP (RFC4226) solution!


## Prerequisites

Language: PHP 8.0/+

_Note: v1.x.x supports PHP 7.x.x series_

## Installation

```
composer require abmmhasan/otp
```

## Why this library?

#### TOTP & HOTP
- Uses offline QR code generator (no more exposing your secret online)
- Time-safe Base32 encoding (30 seconds validity means 30 seconds, I'm not kidding)

#### Generic OTP
- No need to dedicate extra storage/db for User information (just build your unique signature)

## Usage

### HOTP (RFC4226)

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = \AbmmHasan\OTP\HOTP::generateSecret();

/**
* Get QR Code Image for secret $secret
*/
(new \AbmmHasan\OTP\HOTP($secret))->getQRImage('TestName', 'TestTitle');

/**
* Get current OTP for a given counter
*/
$counter = 346;
$otp = (new \AbmmHasan\OTP\HOTP($secret))->getOTP($counter);

/**
* Verify
*/
(new \AbmmHasan\OTP\HOTP($secret))->verify($otp,$counter);
```

### TOTP (RFC6238)

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = \AbmmHasan\OTP\TOTP::generateSecret();

/**
* Get QR Code Image for secret $secret
*/
(new \AbmmHasan\OTP\TOTP($secret))->getQRImage('TestName', 'TestTitle');

/**
* Get current OTP
*/
$otp = (new \AbmmHasan\OTP\TOTP($secret))->getOTP();
// or get OTP for another specified epoch time
$otp = (new \AbmmHasan\OTP\TOTP($secret))->getOTP(1604820275);

/**
* Verify
*/
(new \AbmmHasan\OTP\TOTP($secret))->verify($otp);
// or verify for a specified time
(new \AbmmHasan\OTP\TOTP($secret))->verify($otp, 1604820275);
```

### Generic OTP

```php
/**
* Initiate (Param 1 is OTP length, Param 2 is validity in seconds) 
*/
$otpInstance = new \AbmmHasan\OTP\OTP(4, 60);

/**
* Generate & get the OTP
*/
$otp = $otpInstance->generate('an unique signature for a cause');

/**
* Verify the OTP
*/
$otpInstance->verify('an unique signature for a cause', $otp);
```
_Note: Generic OTP uses **temporary location** for storage, make sure you have proper access permission_

## Support

Having trouble? Create an issue!
