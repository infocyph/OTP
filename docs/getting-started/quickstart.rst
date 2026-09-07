Quickstart
==========

This page demonstrates a complete authenticator-app enrollment and login flow.
The dedicated guides cover every parameter and alternative workflow.

Create and persist a factor
---------------------------

Generate a secret and construct TOTP with the interoperable defaults:

.. code-block:: php

   use Infocyph\OTP\TOTP;

   $secret = TOTP::generateSecret();
   $totp = new TOTP($secret);

Persist ``$secret`` encrypted with a new factor record before showing enrollment
material. Give the record an identifier tied to this exact secret generation:

.. code-block:: php

   $factorId = 'user-42:totp:secret-v1';

Do not use only ``user-42``. A factor ID is also a replay-state namespace and must
change when the secret, suite, or moving-factor generation changes.

Build enrollment material
-------------------------

The account label and issuer are separate arguments:

.. code-block:: php

   $payload = $totp->getEnrollmentPayload(
       label: 'alice@example.com',
       issuer: 'Example App',
       withQrSvg: true,
       imageSize: 256,
   );

   $payload->secret; // normalized Base32
   $payload->uri;    // otpauth://totp/...
   $payload->qrSvg;  // SVG string

Render the SVG directly in a protected enrollment response. Treat all three
values as credentials. Never write them to a public asset directory, log, error
tracker, analytics payload, or long-lived browser cache.

Confirm enrollment
------------------

Ask the user to enter one code from the newly enrolled app:

.. code-block:: php

   $confirmation = $totp->verifyWithWindow(
       otp: $submittedCode,
       timestamp: null,
   );

   if (!$confirmation->matched) {
       // Keep the factor pending and show a generic validation failure.
   }

Only activate the persisted factor after confirmation succeeds. If enrollment
is abandoned, delete the pending secret and its replay state.

Verify a login with replay protection
-------------------------------------

Production verification should use one shared, fail-closed,
integrity-protected, authoritative CacheLayer backend. CacheLayer 3.3 exposes
native atomics on capable backends and the corresponding coordinated lock on
lock-backed fallbacks, so OTP receives one authentication-state configuration
unit. This Redis example uses the native atomic path and rejects object/closure
payloads:

.. code-block:: php

   use Infocyph\CacheLayer\Cache\Cache;
   use Infocyph\CacheLayer\Cache\CacheOptions;
   use Infocyph\OTP\ValueObjects\VerificationWindow;
   use Infocyph\OTP\VerificationReason;

   $redis = new Redis();
   $redis->connect('127.0.0.1', 6379, 1.0);

   $stateCache = Cache::redis(
       namespace: 'infocyph-otp',
       client: $redis,
       options: new CacheOptions(
           integrityKey: $cacheIntegrityKey,
           allowClosures: false,
           allowObjects: false,
           failOpen: false,
       ),
   );
   $result = $totp->verifyWithWindow(
       otp: $submittedCode,
       timestamp: null,
       window: new VerificationWindow(past: 1, future: 1),
       cache: $stateCache,
       factorId: $factorId,
   );

   if ($result->matched) {
       // Complete authentication, rotate the session ID, and audit without OTP data.
   } elseif ($result->reason === VerificationReason::Replay) {
       // Fail closed; the code or a newer timestep was already accepted.
   } else {
       // Malformed or mismatched credentials. Return a generic client message.
   }

Cache and factor ID are an all-or-nothing group. TOTP atomically advances the
factor's last accepted timestep with CacheLayer native conditional state when
available; a backend without atomics uses CacheLayer's coordinated lock. Only
one concurrent request can accept the same code and a higher accepted timestep
can never be replaced by a lower one. Fail-open, unsigned,
tiered/non-authoritative, and coordination-incapable caches are rejected. A
selected atomic backend failure propagates and is never retried through the lock
fallback. Do not use ``Cache::remember()`` for authentication mutations because
it does not express these compare/claim semantics.

Boolean verification
--------------------

For a local calculation where replay state is not required:

.. code-block:: php

   $valid = $totp->verify(
       otp: $submittedCode,
       timestamp: null,
       pastWindows: 1,
       futureWindows: 1,
   );

Do not use this convenience path for an authentication endpoint that promises
single-use acceptance.

Use a non-default profile
-------------------------

SHA-256, eight digits, and a 60-second period are supported:

.. code-block:: php

   $totp = new TOTP(
       secret: $secret,
       digits: 8,
       period: 60,
       algorithm: 'sha256',
   );

Use non-default values only after testing every supported authenticator app.
The generated provisioning URI includes non-default values automatically.

Request lifecycle checklist
---------------------------

A production login request should:

#. load the factor without exposing whether it exists;
#. apply endpoint, account, destination, IP, and device rate limits;
#. decrypt the secret only for the shortest necessary scope;
#. verify with shared atomic replay protection;
#. discard the plaintext secret and submitted code;
#. rotate the authenticated session after success;
#. record a redacted audit event; and
#. return a generic failure response for malformed, mismatched, and replayed
   credentials where detailed disclosure is unnecessary.

Other primitives
----------------

Every main authentication primitive has a dedicated guide with a complete usage
scenario:

* Use :doc:`../guides/generic-otp` for delivered email/SMS/one-time challenges.
* Use :doc:`../guides/hotp` for explicit counters and resynchronization.
* Use :doc:`../guides/totp` for authenticator-app time-based codes.
* Use :doc:`../guides/ocra` for RFC 6287 challenge-response and transaction
  signing inputs.
* Use :doc:`../guides/aotp` for optional Ed25519 asymmetric challenge-response.
* Use :doc:`../guides/grid-otp` for the dynamic human grid knowledge factor.
* Use :doc:`../guides/mobile-otp` for legacy Mobile-OTP/mOTP interoperability.
* Use :doc:`../guides/passkey` for optional WebAuthn registration and
  authentication, including browser code.
* Use :doc:`../guides/recovery-codes` for account recovery.
