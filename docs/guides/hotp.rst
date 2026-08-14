HOTP
====

HOTP is the RFC 4226 counter-based primitive. ``HOTP`` is immutable and does not
store the moving counter; the application remains the source of truth for the
next expected counter.

Construction and generation
---------------------------

.. code-block:: php

   use Infocyph\OTP\HOTP;

   $secret = HOTP::generateSecret();
   $hotp = new HOTP(
       secret: $secret,
       digits: 6,
       algorithm: 'sha1',
   );

   $code = $hotp->generate(counter: 10);

The decoded Base32 secret must contain at least 16 bytes. Generated secrets
contain 20 bytes by default. Digits are 6–9; supported algorithms are ``sha1``,
``sha256``, and ``sha512``. Counters are non-negative and may reach ``PHP_INT_MAX``.

Simple verification
-------------------

.. code-block:: php

   $valid = $hotp->verify(
       otp: $submittedCode,
       counter: $storedNextCounter,
       lookAhead: 0,
   );

This returns only a boolean and does not expose the counter that matched. Use it
when the caller already knows the exact counter and does not need package replay
state.

Detailed verification and resynchronization
-------------------------------------------

.. code-block:: php

   use Infocyph\OTP\VerificationReason;

   $result = $hotp->verifyWithResult(
       otp: $submittedCode,
       counter: $storedNextCounter,
       lookAhead: 10,
   );

   if ($result->matched) {
       $result->matchedCounter;
       $result->nextCounter;
       $result->driftOffset;

       if ($result->reason === VerificationReason::Resynchronized) {
           // The token was ahead by $result->driftOffset counters.
       }
   }

Matching scans from ``counter`` through ``counter + lookAhead``. Look-ahead is
0–100 and the sum must remain within the integer range. An exact match has
reason ``Matched`` and offset zero; a later counter has reason ``Resynchronized``.

Persist ``nextCounter``, never ``matchedCounter``. When ``PHP_INT_MAX`` matches,
``nextCounter`` is null and the factor can no longer advance safely; replace it.

Replay-safe verification
------------------------

.. code-block:: php

   $result = $hotp->verifyWithResult(
       $submittedCode,
       counter: $storedNextCounter,
       lookAhead: 10,
       cache: $stateCache,
       factorId: 'user-42:hotp:secret-v2',
   );

The safe CacheLayer authentication-state cache and factor ID must be supplied
together. The package stores the greatest accepted counter with no TTL.
Acceptance fails with reason ``Replay`` if the stored value is equal or greater,
even if the OTP math matches. Use a durable, non-evicting backend: loss of this
record can reopen older counters.

Application counter persistence and replay advancement are two state systems.
Design their transaction boundary deliberately. A common approach is to keep
both values in the same database and perform verification inside an
application-controlled transaction. Never move the application counter
backward after a retry or partial failure.

Malformed and mismatched results
--------------------------------

A submitted value with the wrong width or non-decimal characters returns
``Malformed``. A correctly shaped value that fails the configured range returns
``Mismatch``. Invalid counter, look-ahead, cache/factor pairing, factor-ID length,
algorithm, secret, or digit configuration throws ``InvalidArgumentException``.

Provisioning
------------

HOTP provisioning always includes the initial counter:

.. code-block:: php

   $uri = $hotp->getProvisioningUri(
       label: 'alice@example.com',
       issuer: 'Example App',
       initialCounter: $storedNextCounter,
       additionalParameters: ['tenant' => 'north'],
   );

   $svg = $hotp->getProvisioningUriQR(
       'alice@example.com',
       'Example App',
       initialCounter: $storedNextCounter,
       imageSize: 256,
   );

   $payload = $hotp->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       initialCounter: $storedNextCounter,
       withQrSvg: true,
   );

The account label must not already contain an issuer prefix. Treat URI, SVG,
payload secret, and recovery copies as credentials.

Counter lifecycle
-----------------

A safe lifecycle is:

#. generate and encrypt the secret;
#. create a versioned factor ID;
#. persist the initial next counter;
#. provision the token with that same counter;
#. verify with bounded look-ahead;
#. atomically persist ``nextCounter`` after acceptance;
#. monitor repeated resynchronization as an operational signal; and
#. rotate the secret and factor ID before counter exhaustion or compromise.

RFC test vector
---------------

The standard 20-byte secret can be used to verify integration behavior:

.. code-block:: php

   $hotp = new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');

   assert($hotp->generate(0) === '755224');
   assert($hotp->generate(1) === '287082');
   assert($hotp->generate(9) === '520489');
