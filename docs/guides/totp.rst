TOTP Guide
==========

RFC context
-----------

TOTP is defined in RFC6238. Conceptually, it is HOTP over a moving time-step instead of a manually tracked counter.

The usual flow is:

- client and server share a secret
- both derive the current time-step from the current Unix timestamp
- both generate the OTP from that time-step
- the server verifies the submitted OTP inside an allowed drift window

This package exposes both the simple boolean verification flow and a richer result-based flow for drift and replay handling.

Generating a secret
-------------------

You can generate a new Base32 secret directly from the TOTP class:

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $secret = TOTP::generateSecret();

If you want to control the random byte length:

.. code-block:: php

   <?php
   $secret = TOTP::generateSecret(64);

Creating a TOTP instance
------------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $totp = new TOTP($secret, digitCount: 6, period: 30);

Key parameters:

- ``secret`` is a Base32 secret
- ``digitCount`` is typically ``6`` or ``8``
- ``period`` is the time-step in seconds, commonly ``30``

Generating an OTP
-----------------

.. code-block:: php

   <?php
   $otp = $totp->getOTP();

Generate for a specific timestamp:

.. code-block:: php

   <?php
   $otp = $totp->getOTP(1716532624);

Basic verification
------------------

Use ``verify()`` when a boolean is enough:

.. code-block:: php

   <?php
   $totp->verify($otp);

Or for a specific timestamp:

.. code-block:: php

   <?php
   $totp->verify($otp, timestamp: 1716532624);

Windowed verification
---------------------

Real-world authenticators can drift slightly. RFC6238 deployments commonly allow a small validation window around the current time-step.

This library supports:

- previous windows only
- future windows only
- symmetric windows

Example with both past and future drift:

.. code-block:: php

   <?php
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $totp->verifyWithWindow(
       $otp,
       timestamp: time(),
       window: new VerificationWindow(past: 1, future: 0),
   );

   $result->matched;
   $result->matchedTimestep;
   $result->driftOffset;
   $result->isExact();
   $result->isDrifted();

Another example using the lightweight bool API:

.. code-block:: php

   <?php
   $isValid = $totp->verify(
       $otp,
       timestamp: time(),
       pastWindows: 1,
       futureWindows: 1,
   );

Time helpers
------------

.. code-block:: php

   <?php
   $totp->getCurrentTimeStep();
   $totp->getRemainingSeconds();
   $totp->getTimeStepFromTimestamp(1716532624);

These helpers are useful when you want to:

- display countdown UI
- log or inspect drift
- persist the matched time-step as replay state

Replay protection
-----------------

RFC6238 itself defines the OTP derivation algorithm, but replay prevention is an application responsibility.

Typical server-side policy:

- accept a code once for a given user and time-step
- reject reuse of that accepted time-step

Example with replay-aware verification:

.. code-block:: php

   <?php
   use Infocyph\OTP\Stores\InMemoryReplayStore;
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $store = new InMemoryReplayStore();

   $result = $totp->verifyWithWindow(
       $otp,
       window: new VerificationWindow(past: 1, future: 1),
       replayStore: $store,
       binding: 'user-42',
   );

   $result->matched;
   $result->replayDetected;

Rotation helper
---------------

When rotating a secret, you may want a controlled overlap period:

.. code-block:: php

   <?php
   $rotation = $totp->rotateSecret($newSecret, gracePeriodInSeconds: 3600);

   $rotation['current'];
   $rotation['next'];
   $rotation['overlapUntil'];

Provisioning
------------

TOTP is commonly provisioned into authenticator apps using ``otpauth://`` URIs.

.. code-block:: php

   <?php
   $uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
   $svg = $totp->getProvisioningUriQR('alice@example.com', 'Example App');

Detailed QR setup example:

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

   // store $secret securely and render $svg during enrollment

See :doc:`provisioning` for the full provisioning flow.
