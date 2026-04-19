Provisioning Guide
==================

Provisioning URIs
-----------------

Generate a provisioning URI:

.. code-block:: php

   $uri = $totp->getProvisioningUri('alice@example.com', 'Example App');

Render an SVG QR code:

.. code-block:: php

   $svg = $totp->getProvisioningUriQR('alice@example.com', 'Example App');

Enrollment payloads
-------------------

.. code-block:: php

   $payload = $totp->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       withQrSvg: true,
   );

   $payload->secret;
   $payload->uri;
   $payload->qrPayload;
   $payload->qrSvg;

Parsing existing URIs
---------------------

.. code-block:: php

   use Infocyph\OTP\TOTP;

   $parsed = TOTP::parseProvisioningUri($uri);

   $parsed->type;
   $parsed->secret;
   $parsed->label;
   $parsed->issuer;

Issuer and label behavior
-------------------------

Label formatting is centralized to avoid malformed outputs such as duplicated issuer prefixes.

The provisioning layer:

- normalizes issuers
- safely formats labels
- separates URI generation from QR rendering
