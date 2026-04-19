# Provisioning

## Provisioning URI

```php
$uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
```

## SVG QR rendering

```php
$svg = $totp->getProvisioningUriQR('alice@example.com', 'Example App');
```

## Enrollment payload

```php
$payload = $totp->getEnrollmentPayload(
    'alice@example.com',
    'Example App',
    withQrSvg: true,
);

$payload->secret;
$payload->uri;
$payload->qrPayload;
$payload->qrSvg;
```

## Parse existing `otpauth://` URIs

```php
use Infocyph\OTP\TOTP;

$parsed = TOTP::parseProvisioningUri($uri);

$parsed->type;
$parsed->secret;
$parsed->label;
$parsed->issuer;
```

## Issuer and label behavior

Label formatting is centralized to avoid malformed outputs such as duplicated issuer prefixes.

The provisioning layer:

- normalizes issuers
- safely formats labels
- separates URI generation from QR rendering
