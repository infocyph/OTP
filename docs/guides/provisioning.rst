Provisioning Guide
==================

Overview
--------

Provisioning is the process of preparing a secret and metadata for an authenticator client.

This package separates:

- provisioning URI generation
- QR payload generation
- QR image rendering
- URI parsing

Generating secrets
------------------

For TOTP, HOTP, and OCRA, you can generate a new Base32 secret before building provisioning artifacts:

.. code-block:: php

   <?php
   use Infocyph\OTP\HOTP;
   use Infocyph\OTP\OCRA;
   use Infocyph\OTP\TOTP;

   $totpSecret = TOTP::generateSecret();
   $hotpSecret = HOTP::generateSecret();
   $ocraSharedKey = OCRA::generateSecret();

Provisioning URIs
-----------------

Generate a provisioning URI:

.. code-block:: php

   <?php
   $uri = $totp->getProvisioningUri('alice@example.com', 'Example App');

Render an SVG QR code:

.. code-block:: php

   <?php
   $svg = $totp->getProvisioningUriQR('alice@example.com', 'Example App');

Full TOTP QR example:

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $totp = (new TOTP($secret))
       ->setAlgorithm('sha256');

   $svg = $totp->getProvisioningUriQR(
       'alice@example.com',
       'Example App',
   );

   // return or embed the SVG in your setup page
   echo $svg;

HOTP example:

.. code-block:: php

   <?php
   $uri = $hotp->getProvisioningUri('alice@example.com', 'Example App');

HOTP QR example:

.. code-block:: php

   <?php
   use Infocyph\OTP\HOTP;

   $hotp = (new HOTP($secret))
       ->setCounter(3)
       ->setAlgorithm('sha1');

   $svg = $hotp->getProvisioningUriQR(
       'alice@example.com',
       'Example App',
   );

OCRA example:

.. code-block:: php

   <?php
   $uri = $ocra->getProvisioningUri('alice@example.com', 'Example App');

OCRA QR example:

.. code-block:: php

   <?php
   use Infocyph\OTP\OCRA;

   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', $sharedKey);
   $svg = $ocra->getProvisioningUriQR(
       'alice@example.com',
       'Example App',
   );

Enrollment payloads
-------------------

.. code-block:: php

   <?php
   $payload = $totp->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       withQrSvg: true,
   );

   $payload->secret;
   $payload->uri;
   $payload->qrPayload;
   $payload->qrSvg;

This is useful when your application wants to:

- show a QR code in the UI
- store the raw provisioning URI
- return the same payload to a frontend or admin tool

Example:

.. code-block:: php

   <?php
   $payload = $totp->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       withQrSvg: true,
   );

   $secret = $payload->secret;
   $uri = $payload->uri;
   $svg = $payload->qrSvg;

   // persist $secret securely, store $uri if desired, render $svg in setup UI

Parsing existing URIs
---------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $parsed = TOTP::parseProvisioningUri($uri);

   $parsed->type;
   $parsed->secret;
   $parsed->label;
   $parsed->issuer;
   $parsed->algorithm;
   $parsed->digits;
   $parsed->period;
   $parsed->counter;
   $parsed->ocraSuite;

Issuer and label behavior
-------------------------

Label formatting is centralized to avoid malformed outputs such as duplicated issuer prefixes.

The provisioning layer:

- normalizes issuers
- safely formats labels
- separates URI generation from QR rendering
