# OTP

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/7470c9de3a5848f982b77f005945b04f)](https://app.codacy.com/gh/abmmhasan/OTP/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/abmmhasan/otp)
![Packagist Downloads (custom server)](https://img.shields.io/packagist/dt/abmmhasan/otp?color=green&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Fabmmhasan%2Fotp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/abmmhasan/otp)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/abmmhasan/otp/php)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/abmmhasan/otp)

Simple but Secure TOTP (RFC6238) & HOTP (RFC4226) solution!


## Prerequisites

Language: PHP 7.1/+

## Installation

```
composer require abmmhasan/otp
```

## Why this library?

Most of the OTP library found there (written in PHP) are insecure. Wanna know why?
1. Uses Online URL to generate QR Images (it exposes your secret key, online)
2. Uses basic Base32 functions which is not Time safe (verifies same OTP upto 90 second instead of 30 second)

Well, this library mitigates both problems using [Constant-Time Encoding](https://github.com/paragonie/constant_time_encoding) & [QR Code generator](https://github.com/Bacon/BaconQrCode).
All the data generated are simply on your very own server.

## Usage

### HOTP

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = (new \AbmmHasan\OTP())->createSecret();

/**
* Get QR Code Image for secret $secret
*/
(new \AbmmHasan\OTP())->setSecret($secret)->getQRSnap('hotp','TestName','TestTitle');

/**
* Get current OTP for a given counter
*/
$counter = 346;
$otp = (new \AbmmHasan\OTP())->setSecret($secret)->getHOTP($counter);

/**
* Verify
*/
(new \AbmmHasan\OTP())->setSecret($secret)->verify($otp,$counter);
// or
(new \AbmmHasan\OTP())->setSecret($secret)->verify($otp,$counter,'hotp');
```

### TOTP

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = (new \AbmmHasan\OTP())->createSecret();

/**
* Get QR Code Image for secret $secret
*/
(new \AbmmHasan\OTP())->setSecret($secret)->getQRSnap('totp','TestName','TestTitle');

/**
* Get current OTP
*/
$otp = (new \AbmmHasan\OTP())->setSecret($secret)->getTOTP();
// or get OTP for another specified epoch time
$otp = (new \AbmmHasan\OTP())->setSecret($secret)->getTOTP(1604820275);
/**
* Verify current OTP
*/
(new \AbmmHasan\OTP())->setSecret($secret)->verify($otp);
// or verify for a specified time
(new \AbmmHasan\OTP())->setSecret($secret)->verify($otp,1604820275,'totp');
```

## Support

Having trouble? Create an issue!
