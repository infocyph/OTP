Provisioning
============

The package builds and strictly parses ``otpauth://`` URIs for TOTP, HOTP, and the
library's OCRA convention. URI and QR values contain the plaintext factor secret
and must be handled as credentials.

Protocol convenience methods
----------------------------

TOTP:

.. code-block:: php

   $uri = $totp->getProvisioningUri(
       label: 'alice@example.com',
       issuer: 'Example App',
       additionalParameters: ['tenant' => 'north'],
   );

   $svg = $totp->getProvisioningUriQR(
       'alice@example.com',
       'Example App',
       imageSize: 256,
   );

HOTP includes the explicit initial counter:

.. code-block:: php

   $uri = $hotp->getProvisioningUri(
       label: 'alice@example.com',
       issuer: 'Example App',
       initialCounter: 9,
   );

OCRA includes suite, algorithm, and digit parameters:

.. code-block:: php

   $uri = $ocra->getProvisioningUri(
       'alice@example.com',
       'Example App',
   );

Enrollment payload
------------------

Each protocol exposes ``getEnrollmentPayload()``:

.. code-block:: php

   $payload = $totp->getEnrollmentPayload(
       label: 'alice@example.com',
       issuer: 'Example App',
       additionalParameters: ['tenant' => 'north'],
       withQrSvg: true,
       imageSize: 256,
   );

   $payload->secret;
   $payload->uri;
   $payload->issuer;
   $payload->label;
   $payload->qrSvg;

``qrSvg`` is null unless requested. The payload URI and SVG are generated from the
same configuration. Render them only in authenticated enrollment pages with
appropriate cache controls.

Labels and issuers
------------------

Pass an account label without an issuer prefix:

.. code-block:: php

   $totp->getProvisioningUri('alice@example.com', 'Example App');

Do not pass ``Example App:alice@example.com`` as the label. The builder creates
that combined URI path. Issuers cannot contain colons. Labels and issuers are
trimmed and must be non-empty, valid UTF-8 without control characters. The final
combined label is limited to 255 UTF-8 bytes.

When parsing, an issuer in the label path and an ``issuer`` query value must agree.
Ambiguous or conflicting identity is rejected. The parsed account portion is
normalized with the same colon-free rule as builder input, so
``Issuer:alice:extra`` is invalid; ``:alice`` retains an account without a label
issuer.

Default emission
----------------

For compatibility, default TOTP values are omitted:

* SHA-1 algorithm;
* six digits; and
* 30-second period.

Non-default values are included automatically. HOTP always emits ``counter``,
including zero. OCRA always emits ``algorithm``, ``digits``, and ``ocraSuite``.

Additional parameters
---------------------

Unknown extension parameters can be added:

.. code-block:: php

   $uri = $totp->getProvisioningUri(
       'alice@example.com',
       'Example App',
       ['tenant' => 'north', 'image' => 'https://example.test/icon.png'],
   );

At most 24 extension parameters may be supplied. Keys must contain 1–64
printable bytes; string values may contain at most 1024 bytes. Imported unknown
extensions use the same per-key and per-value limits. Values may be
scalar or null. These names are reserved case-insensitively and cannot be
overridden:

* ``secret``;
* ``issuer``;
* ``algorithm``;
* ``digits``;
* ``period``;
* ``counter``; and
* ``ocraSuite``.

Parse imported URIs
-------------------

.. code-block:: php

   use Infocyph\OTP\Support\ProvisioningUriParser;

   $parsed = ProvisioningUriParser::parse($uri);

   $parsed->type;
   $parsed->secret;
   $parsed->label;
   $parsed->issuer;
   $parsed->algorithm;
   $parsed->digits;
   $parsed->period;
   $parsed->counter;
   $parsed->ocraSuite;
   $parsed->additionalParameters;

The parser normalizes Base32 and algorithm names. Missing optional defaults are
materialized in the result:

* algorithm defaults to ``sha1``;
* digits default to 6; and
* TOTP period defaults to 30.

Unknown query parameters are preserved as strings in ``additionalParameters``.

Round-trip an imported configuration
------------------------------------

.. code-block:: php

   use Infocyph\OTP\Support\ProvisioningUriBuilder;

   $rebuilt = ProvisioningUriBuilder::build(
       type: $parsed->type,
       secret: $parsed->secret,
       label: $parsed->label,
       issuer: $parsed->issuer
           ?? throw new InvalidArgumentException('An issuer is required to rebuild.'),
       include: [
           'algorithm' => $parsed->algorithm !== 'sha1'
               || $parsed->type === 'ocra',
           'digits' => $parsed->digits !== 6
               || $parsed->type === 'ocra',
           'period' => $parsed->type === 'totp'
               && $parsed->period !== 30,
           'counter' => $parsed->type === 'hotp',
       ],
       additionalParameters: $parsed->additionalParameters,
       algorithm: $parsed->algorithm,
       digits: $parsed->digits,
       period: $parsed->period,
       counter: $parsed->counter,
       ocraSuite: $parsed->ocraSuite,
   );

Most applications should prefer protocol convenience methods. The lower-level
builder is useful for import/export tools that already possess a parsed generic
configuration. Parsing accepts a URI without an issuer, but this package's
builder requires an explicit non-empty issuer; an import tool must obtain one
before rebuilding such a URI.

Strict parser rejection
-----------------------

The parser rejects:

* empty input and URIs over 4096 bytes;
* schemes other than ``otpauth``;
* unsupported hosts/types;
* embedded username/password, ports, and fragments;
* missing, weak, oversized, or invalid secrets (accepted factor secrets decode
  to 16–1024 bytes);
* invalid percent encoding;
* empty or duplicate query parameters;
* control characters in names;
* reserved query parameters with non-canonical casing;
* integer overflow and invalid numeric syntax;
* HOTP without a counter;
* counter outside HOTP;
* period outside TOTP;
* OCRA suite outside OCRA;
* missing OCRA suite;
* OCRA algorithm/digit disagreement with the suite; and
* invalid label/issuer identity; and
* unknown extension keys above 64 bytes or values above 1024 bytes.

Catch ``InvalidArgumentException`` at an import boundary and show a generic
“unsupported or invalid QR code” message. Do not echo the rejected URI into logs
or errors.

QR rendering
------------

``getProvisioningUriQR()`` and ``SvgQrRenderer::render()`` produce an SVG string.
The image size must be within the renderer's accepted range. SVG is generated
from the URI and therefore contains the secret indirectly. Apply the same
authorization, transport, retention, and logging rules as the raw secret.

Client interoperability
-----------------------

``otpauth`` behavior is an ecosystem convention. TOTP defaults are most portable.
HOTP, SHA-256/SHA-512, non-default digit/period values, extension parameters,
and especially OCRA require testing against exact client versions. See
:doc:`authenticator-apps`.
