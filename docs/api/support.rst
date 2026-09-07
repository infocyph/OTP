Support API
===========

Most applications should use ``HOTP``, ``TOTP``, ``OCRA``, ``GenericOtp``, and
``RecoveryCodes`` directly. Support classes are public for import/export tooling,
custom enrollment flows, validation, and advanced integrations.

SecretUtility
-------------

.. code-block:: php

   use Infocyph\OTP\Support\SecretUtility;

   $secret = SecretUtility::generate(bytes: 20);
   $normalized = SecretUtility::normalizeBase32($userInput);
   $binary = SecretUtility::decodeBase32($normalized);
   $strongBinary = SecretUtility::requireStrongBase32($normalized);
   $valid = SecretUtility::isValidBase32($userInput);

``generate()`` accepts 16–1024 bytes. Normalization removes spaces, tabs, line
breaks, hyphens, surrounding whitespace, and Base32 padding, then uppercases.
Decoding verifies canonical round-trip encoding. ``requireStrongBase32()``
requires 16–1024 decoded bytes.

AlgorithmValidator
------------------

.. code-block:: php

   use Infocyph\OTP\Support\AlgorithmValidator;

   $algorithm = AlgorithmValidator::normalize(' SHA256 '); // "sha256"
   $supported = AlgorithmValidator::supported();          // sha1/sha256/sha512

Unsupported names throw ``InvalidArgumentException``.

ProvisioningUriBuilder
----------------------

.. code-block:: php

   use Infocyph\OTP\Support\ProvisioningUriBuilder;

   $uri = ProvisioningUriBuilder::build(
       type: 'totp',
       secret: $secret,
       label: 'alice@example.com',
       issuer: 'Example App',
       include: [
           'algorithm' => true,
           'digits' => true,
           'period' => true,
       ],
       additionalParameters: ['tenant' => 'north'],
       algorithm: 'sha256',
       digits: 8,
       period: 60,
   );

The builder also supports ``hotp`` with a required counter and ``ocra`` with a
required suite whose algorithm/digits agree. Protocol convenience methods infer
``include`` flags and are less error-prone for normal enrollment.

``enrollmentPayload()`` builds a generic immutable payload when a custom flow
already has all configuration values:

.. code-block:: php

   $payload = ProvisioningUriBuilder::enrollmentPayload(
       type: 'totp',
       secret: $secret,
       label: 'alice@example.com',
       issuer: 'Example App',
       include: [],
   );

An optional ``qrSvg`` argument is attached as supplied; this method does not
render the URI itself.

ProvisioningUriParser
---------------------

.. code-block:: php

   use Infocyph\OTP\Support\ProvisioningUriParser;

   $parsed = ProvisioningUriParser::parse($untrustedUri);

The parser is strict and bounded. It returns ``ParsedOtpAuthUri`` with effective
defaults and preserved unknown extensions. See :doc:`../guides/provisioning` for
the complete rejection rules and round-trip example.

SvgQrRenderer
-------------

.. code-block:: php

   use Infocyph\OTP\Support\SvgQrRenderer;

   $svg = SvgQrRenderer::render(
       payload: $uri,
       imageSize: 256,
   );

Payload length is 1–4096 bytes and image size is 64–4096 pixels. The SVG embeds
credential data indirectly and is sensitive.

LabelHelper
-----------

.. code-block:: php

   use Infocyph\OTP\Support\LabelHelper;

   $label = LabelHelper::normalizeAccountLabel('alice@example.com');
   $issuer = LabelHelper::normalizeIssuer('Example   App');
   $formatted = LabelHelper::formatLabel($label, $issuer);
   $parts = LabelHelper::parseLabel(rawurlencode($formatted), $issuer);

Text must contain 1–255 valid UTF-8 bytes without control characters. Account
labels and issuers cannot contain a colon. Issuer internal whitespace is
collapsed. Parsing rejects invalid percent encoding and issuer conflicts.

OtpMath
-------

.. code-block:: php

   use Infocyph\OTP\Support\OtpMath;

   $otp = OtpMath::hotp(
       secret: $base32Secret,
       counter: 0,
       digits: 6,
       algorithm: 'sha1',
   );

``hotpFromBinary()`` is available when a validated binary secret is already held.
These methods perform calculation only; they do not validate factor-strength
policy, persist counters, apply look-ahead, or protect replay. Prefer ``HOTP`` or
``TOTP`` unless building a protocol adapter.

Internal support
----------------

``CacheLock`` and ``SecretRotationPlanner`` are marked ``@internal``. They are
implementation details, not supported application entry points. Use protocol
``planRotation()`` methods for rotation. Replay-aware protocols consume
CacheLayer 3.3 native atomic state when available and use the cache-owned lock as
a fallback; ``GenericOtp`` continues to use the lock-backed state machine.
Applications should not call or depend on these internal coordination helpers.

Internal versus workflow responsibility
---------------------------------------

Public support methods provide bounded transformations. They do not authorize
an import, persist a factor, prove activation, apply rate limits, or make a
security policy decision. Keep those decisions at the application boundary.
