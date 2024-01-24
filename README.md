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

Language: PHP 8.2/+

| Library Version | PHP Version     |
|-----------------|-----------------|
| 3.x.x           | 8.2.x or Higher |
| 2.x.x           | 8.x.x           |
| 1.x.x           | 7.x.x           |

## Installation

```
composer require abmmhasan/otp
```

## Why this library?

#### TOTP & HOTP
- Uses offline QR code generator (no more exposing your secret online)
- Time-safe Base32 encoding (30 seconds validity means 30 seconds)

#### Generic OTP
- No need to dedicate extra storage/db for User information (just build a unique signature)

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
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \AbmmHasan\OTP\HOTP($secret))
// only required if the counter is being imported from another system or if it is old, & for QR only
->setCounter(3)
// default is sha1; Caution: many app (in fact, most of them) have algorithm limitation
->setAlgorithm('sha256') 
// or `getProvisioningUri` just to get the URI
->getProvisioningUriQR('TestName', 'abc@def.ghi'); 

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
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \AbmmHasan\OTP\TOTP($secret)) 
// default is sha1; Caution: many app (in fact, most of them) have algorithm limitation
->setAlgorithm('sha256') 
// or `getProvisioningUri` just to get the URI
->getProvisioningUriQR('TestName', 'abc@def.ghi');

/**
* Get current OTP
*/
$otp = (new \AbmmHasan\OTP\TOTP($secret))->getOTP();
// or get OTP for another specified epoch time
$otp = (new \AbmmHasan\OTP\TOTP($secret))->getOTP(1604820275);

/**
* Verify
* 
* on 3rd parameter it supports, enabling leeway.
* if enabled, it will also check with last segment's generated otp 
*/
(new \AbmmHasan\OTP\TOTP($secret))->verify($otp);
// or verify for a specified time
(new \AbmmHasan\OTP\TOTP($secret))->verify($otp, 1604820275);
```

### Generic OTP

```php
/**
* Initiate 
* Param 1 is OTP length (default 6)
* Param 2 is validity in seconds (default 30)
* Param 3 is retry count on failure (default 3)
*/
$otpInstance = new \AbmmHasan\OTP\OTP(4, 60, 2);

/**
* Generate & get the OTP
*/
$otp = $otpInstance->generate('an unique signature for a cause');

/**
* Verify the OTP
* 
* on 3rd parameter setting false will keep the record till the otp is verified or expired
* by default it will keep the record till the key name match or the otp is verified or expired
*/
$otpInstance->verify('an unique signature for a cause', $otp);

/**
* Delete the record
*/
$otpInstance->delete('an unique signature for a cause');

/**
* Flush all the existing OTPs (if any)
*/
$otpInstance->flush()
```
_Note: Generic OTP uses **temporary location** for storage, make sure you have proper access permission_

## Support

Having trouble? Create an issue!
