# OTP

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1b7873dd2bdf48748c86265f24db0b34)](https://app.codacy.com/gh/infocyph/OTP/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/infocyph/otp)
![Packagist Downloads (custom server)](https://img.shields.io/packagist/dt/infocyph/otp?color=green&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2Fotp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/otp)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/otp/php)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/infocyph/otp)

Simple but Secure AIO OTP solution. Supports,
- Generic OTP (storage-less otp solution)
- TOTP (RFC6238)
- HOTP (RFC4226)
- OCRA (RFC6287)

## Table of Contents

<!--ts-->

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Why this library?](#why-this-library)
* [Usage](#usage)
    * [HOTP (RFC4226)](#hotp-rfc4226)
    * [TOTP (RFC6238)](#totp-rfc6238)
    * [OCRA (RFC6287)](#ocra-rfc6287)
    * [Generic OTP](#generic-otp)
* [Support](#support)
* [References](#references)

<!--te-->

## Prerequisites

Language: PHP 8.2/+

| Library Version | PHP Version     |
|-----------------|-----------------|
| 3.x.x/+         | 8.2.x or Higher |
| 2.x.x           | 8.x.x           |
| 1.x.x           | 7.x.x           |

## Installation

```
composer require infocyph/otp
```

## Why this library?

#### TOTP & HOTP
- Uses offline QR code generator (no more exposing your secret online)
- Time-safe Base32 encoding (30 seconds validity means 30 seconds)

#### Generic OTP
- No need to dedicate extra storage/db for User information (just build a unique signature)

#### OCRA
- One of a few implementation in PHP, easy to use

## Usage

### HOTP (RFC4226)

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = \Infocyph\OTP\HOTP::generateSecret();

/**
* Get QR Code Image for secret $secret
*/
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \Infocyph\OTP\HOTP($secret))
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
$otp = (new \Infocyph\OTP\HOTP($secret))->getOTP($counter);

/**
* Verify
*/
(new \Infocyph\OTP\HOTP($secret))->verify($otp,$counter);
```

### TOTP (RFC6238)

```php
/**
* Generate Secret
* It will generate secure random secret string
*/
$secret = \Infocyph\OTP\TOTP::generateSecret();

/**
* Get QR Code Image for secret $secret
*/
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \Infocyph\OTP\TOTP($secret)) 
// default is sha1; Caution: many app (in fact, most of them) have algorithm limitation
->setAlgorithm('sha256') 
// or `getProvisioningUri` just to get the URI
->getProvisioningUriQR('TestName', 'abc@def.ghi');

/**
* Get current OTP
*/
$otp = (new \Infocyph\OTP\TOTP($secret))->getOTP();
// or get OTP for another specified epoch time
$otp = (new \Infocyph\OTP\TOTP($secret))->getOTP(1604820275);

/**
* Verify
* 
* on 3rd parameter it supports, enabling leeway.
* if enabled, it will also check with last segment's generated otp 
*/
(new \Infocyph\OTP\TOTP($secret))->verify($otp);
// or verify for a specified time
(new \Infocyph\OTP\TOTP($secret))->verify($otp, 1604820275);
```

### OCRA (RFC6287)

```php
// Example usage:
$sharedKey = 'mySecretKey'; // Replace with your actual shared key (binary format)
$challenge = '123456'; // Replace with your challenge value
$counter = 0; // Replace with the appropriate counter value

// Create an OCRA suite instance
$suite = new \Infocyph\OTP\OCRA('OCRA-1:HOTP-SHA1-6:C-QN08', $sharedKey);

// Generate the OCRA value
$suite->generate($challenge, $counter);
```

### Generic OTP

```php
/**
* Initiate 
* Param 1 is OTP length (default 6)
* Param 2 is validity in seconds (default 30)
* Param 3 is retry count on failure (default 3)
*/
$otpInstance = new \Infocyph\OTP\OTP(4, 60, 2);

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

## References

- HOTP (RFC4226): https://tools.ietf.org/html/rfc4226
- TOTP (RFC6238): https://tools.ietf.org/html/rfc6238
- OCRA (RFC6287): https://tools.ietf.org/html/rfc6287
