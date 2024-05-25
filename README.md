# OTP

[![Security & Standards](https://github.com/infocyph/OTP/actions/workflows/build.yml/badge.svg)](https://github.com/infocyph/OTP/actions/workflows/build.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1b7873dd2bdf48748c86265f24db0b34)](https://app.codacy.com/gh/infocyph/OTP/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
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
    * [Generic OTP](#generic-otp)
    * [OCRA (RFC6287)](#ocra-rfc6287)
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

- Generate secret
```php
$secret = \Infocyph\OTP\HOTP::generateSecret();
```
- Get QR Code Image for secret $secret (in SVG format)
```php
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \Infocyph\OTP\HOTP($secret))
// only required if the counter is being imported from another system or if it is old, & for QR only
->setCounter(3)
// default is sha1; Caution: many app (in fact, most of them) have algorithm limitation
->setAlgorithm('sha256') 
// or `getProvisioningUri` just to get the URI
->getProvisioningUriQR('TestName', 'abc@def.ghi'); 
```
> The `getProvisioningUriQR` & `getProvisioningUri` accepts 3rd parameter, where it takes array of parameters
`['algorithm', 'digits', 'period', 'counter']`. Problem you might encounter, with the URI/Image is that most of the 
OTP generator might not support all of those options. In that case, passing in a blank array will remove all the optional
keys, or you can pass in selective parameters as you need.

- Get current OTP for a given counter
```php
$counter = 346;
$otp = (new \Infocyph\OTP\HOTP($secret))->getOTP($counter);
```
- Verify
```php
(new \Infocyph\OTP\HOTP($secret))->verify($otp,$counter);
```

### TOTP (RFC6238)

- Generate secret
```php
$secret = \Infocyph\OTP\TOTP::generateSecret();
```
- Get QR Code Image for secret $secret (in SVG format)
```php
// supports digit count in 2nd parameter, recommended to be either 6 or 8 (default 6)
(new \Infocyph\OTP\TOTP($secret))
// default is sha1; Caution: many app (in fact, most of them) have algorithm limitation
->setAlgorithm('sha256') 
// or `getProvisioningUri` just to get the URI
->getProvisioningUriQR('TestName', 'abc@def.ghi'); 
```
> The `getProvisioningUriQR` & `getProvisioningUri` accepts 3rd parameter, where it takes array of parameters
`['algorithm', 'digits', 'period', 'counter']`. Problem you might encounter, with the URI/Image is that most of the
OTP generators might not support all of those options. In that case, passing in a blank array will remove all the optional
keys, or you can pass in selective parameters as you need.

- Get current OTP for a given counter
```php
$counter = 346;
$otp = (new \Infocyph\OTP\TOTP($secret))->getOTP($counter);
// or get OTP for another specified epoch time
$otp = (new \Infocyph\OTP\TOTP($secret))->getOTP(1604820275);
```
- Verify
```php
(new \Infocyph\OTP\TOTP($secret))->verify($otp);
// or verify for a specified time
(new \Infocyph\OTP\TOTP($secret))->verify($otp, 1604820275);
```
> On 3rd parameter `(bool)` it supports, enabling leeway. If enabled, it will also check with last segment's generated otp.

### Generic OTP

- Initiate
```php
/**
* Param 1 is OTP length (default 6)
* Param 2 is validity in seconds (default 30)
* Param 3 is retry count on failure (default 3)
*/
$otpInstance = new \Infocyph\OTP\OTP(4, 60, 2);
```
- Generate & get the OTP
```php
$otp = $otpInstance->generate('an unique signature for a cause');
```
- Verify the OTP
```php
/**
* Verify the OTP
* 
* on 3rd parameter setting false will keep the record till the otp is verified or expired
* by default it will keep the record till the key name match or the otp is verified or expired
*/
$otpInstance->verify('an unique signature for a cause', $otp);
```
> On 3rd parameter setting false `will keep the record till the otp is verified or expired`. By default, 
`will keep the record till the key name match or the otp is verified or expired`

- Delete a record
```php
$otpInstance->delete('an unique signature for a cause');
```
- Flush all the existing OTPs (if any)

```php
$otpInstance->flush()
```

> Generic OTP uses **temporary location** for storage, make sure you have proper access permission

### OCRA (RFC6287)

```php
// Example usage:
$sharedKey = 'mySecretKey'; // Replace with your actual shared key (binary format)
$challenge = '123456'; // Replace with your challenge value
$counter = 0; // Replace with the appropriate counter value

// Create an OCRA instance
$suite = new \Infocyph\OTP\OCRA('OCRA-1:HOTP-SHA1-6:C-QN08', $sharedKey);

// If the OCRA suite supports session, set the session
$suite->setSession('...');

// If the OCRA suite supports time format, set the time
$suite->setTime(new \DateTime());

// If the OCRA suite supports pin, set the pin
$suite->setPin('...');

// Generate the OCRA value
$suite->generate($challenge, $counter);
```

#### Forming an OCRA Suite

According to current RFC6287, an example string should be in the following format:

```php
OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1
```

Here `OCRA-1:HOTP-` is fixed as of current documentation.

- SHA1 is cryptographic hash function. (supported: SHA1, SHA256, SHA512)
- 6 is the number of digits in the generated OTP. (supported: 0, 4-10)
- C denotes counter support (optional)
- QN08 denotes the mode (it can be either of QNxx, QAxx, QHxx)

|    Format (F)    | Up to Length (xx) |
|:----------------:|:-----------------:|
| A (alphanumeric) |       04-64       |
|   N (numeric)    |       04-64       |
| H (hexadecimal)  |       04-64       |

- Next part is optional & little tricky
    - PSHA1 denotes the hash function used for pin support (it can be either of PSHA1, PSHA256, PSHA512)
    - S (not in example) denotes session length (3 digits)
    - T (not in example) denotes time format as of below table,

| Time-Step Size (G) |           Examples           |
|:------------------:|:----------------------------:|
|      [1-59]S       | number of seconds, e.g., 20S |
|      [1-59]M       | number of minutes, e.g., 5M  |
|      [0-48]H       |  number of hours, e.g., 24H  |

## Support

Having trouble? Create an issue!

## References

- HOTP (RFC4226): https://tools.ietf.org/html/rfc4226
- TOTP (RFC6238): https://tools.ietf.org/html/rfc6238
- OCRA (RFC6287): https://tools.ietf.org/html/rfc6287
