HOTP Guide
==========

RFC context
-----------

HOTP is defined in RFC4226. Unlike TOTP, it is driven by a moving counter rather than wall-clock time.

That means:

- both sides must agree on a counter
- every successful authentication normally advances the server-side counter state
- resynchronization is a practical concern in real deployments

Basic usage
-----------

Generating a secret
-------------------

You can generate a new Base32 secret directly from the HOTP class:

.. code-block:: php

   use Infocyph\OTP\HOTP;

   $secret = HOTP::generateSecret();

Creating an HOTP instance
-------------------------

.. code-block:: php

   use Infocyph\OTP\HOTP;

   $hotp = (new HOTP($secret))
       ->setCounter(3)
       ->setAlgorithm('sha1');

   $otp = $hotp->getOTP(10);
   $hotp->verify($otp, 10);

Generating OTPs
---------------

.. code-block:: php

   $counter = 346;
   $otp = $hotp->getOTP($counter);

Basic verification
------------------

.. code-block:: php

   $isValid = $hotp->verify($otp, 346);

Look-ahead verification
-----------------------

HOTP often needs controlled counter resynchronization.

.. code-block:: php

   $hotp->verify($otp, counter: 10, lookAhead: 5);

This means the verifier will try the provided counter and then probe forward up to the configured look-ahead window.

Rich verification result
------------------------

.. code-block:: php

   use Infocyph\OTP\Stores\InMemoryReplayStore;

   $result = $hotp->verifyWithResult(
       $otp,
       counter: 10,
       lookAhead: 5,
       replayStore: new InMemoryReplayStore(),
       binding: 'device-1',
   );

   $result->matched;
   $result->matchedCounter;
   $result->driftOffset;
   $result->replayDetected;

Typical server pattern
----------------------

In a stateful HOTP deployment, a common flow is:

1. load the user or device counter
2. verify using a small look-ahead window
3. if matched, persist the returned ``matchedCounter``
4. reject any already-used counter value

Example:

.. code-block:: php

   $storedCounter = 100;

   $result = $hotp->verifyWithResult(
       $submittedOtp,
       counter: $storedCounter,
       lookAhead: 5,
       replayStore: $store,
       binding: 'device-1',
   );

   if ($result->matched) {
       $nextCounter = $result->matchedCounter;
       // persist the new server-side counter state
   }

Provisioning
------------

HOTP is also commonly shared via ``otpauth://`` URIs, especially when interoperating with authenticator clients that support event-based counters.

.. code-block:: php

   $uri = $hotp->getProvisioningUri('alice@example.com', 'Example App');

QR example:

.. code-block:: php

   $svg = $hotp->getProvisioningUriQR('alice@example.com', 'Example App');

See :doc:`provisioning` for additional provisioning and QR examples.
