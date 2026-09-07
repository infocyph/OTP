Application workflows
=====================

The library exposes cryptographic and atomic-storage primitives. This guide
shows how those primitives fit into complete application scenarios.

Authenticator enrollment
------------------------

#. Create a pending factor record with a unique generation ID.
#. Generate a secret with ``TOTP::generateSecret()``.
#. Encrypt the secret before persistence.
#. Build an ``EnrollmentPayload`` with a URI and optional SVG.
#. Show enrollment material only in an authenticated, non-cacheable response.
#. Ask for a code and verify it against the pending factor.
#. Activate the factor only after confirmation succeeds.
#. Delete abandoned pending records and related replay state.

.. code-block:: php

   use Infocyph\OTP\TOTP;

   $secret = TOTP::generateSecret();
   $factorId = 'user-42:totp:secret-v1';
   $totp = new TOTP($secret);

   $payload = $totp->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       withQrSvg: true,
   );

   // Persist encrypted $secret and pending $factorId before returning $payload.

Login verification
------------------

Perform rate-limit and account checks before expensive verification, but use a
uniform outward response that does not reveal whether an account or factor
exists.

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $totp->verifyWithWindow(
       $submittedCode,
       window: new VerificationWindow(1, 1),
       cache: $stateCache,
       factorId: $factorId,
   );

   if ($result->matched) {
       // Atomically complete the login, rotate the session, and write a redacted audit event.
   }

A cryptographic match rejected by replay state is not a successful result.
Fail closed when the shared CacheLayer backend or the selected coordination
capability (native atomics or lock fallback) is unavailable.

Email or SMS challenge
----------------------

Create a random flow identifier rather than binding only to the user:

.. code-block:: php

   use Infocyph\OTP\GenericOtp;

   $challengeId = bin2hex(random_bytes(16));
   $binding = 'login:user-42:' . $challengeId;

   $service = new GenericOtp(
       cache: $stateCache,
       key: $genericOtpHmacKey,
       ttlSeconds: 300,
       maxAttempts: 3,
   );

   $plainCode = $service->generate($binding);
   $delivery->send($destination, $plainCode);

The application should store the challenge ID in the flow/session, suppress the
plaintext after delivery, enforce resend cooldowns, and ensure the final login
transition is tied to the same flow. Calling ``generate()`` again for the same
binding replaces the old code.

Resend workflow
---------------

Choose one policy and document it:

* reuse the existing delivery without calling ``generate()``; or
* call ``generate()`` to replace the code, making all older messages invalid.

A resend must not reset endpoint/account rate-limit budgets. Package expiration
is absolute for each issued record, while each replacement receives a new
absolute expiration.

HOTP resynchronization
----------------------

Store the next expected counter. A bounded look-ahead can find a token that was
advanced without the server:

.. code-block:: php

   $result = $hotp->verifyWithResult(
       $submittedCode,
       counter: $storedNextCounter,
       lookAhead: 10,
       cache: $stateCache,
       factorId: $factorId,
   );

   if ($result->matched) {
       $storedNextCounter = $result->nextCounter;
   }

Persist ``nextCounter`` in the same application transaction as the successful
authentication where possible. Large look-ahead values increase work and the
range of acceptable token state; the package caps look-ahead at 100.

Recovery-code fallback
----------------------

Recovery should be a distinct, strongly authenticated route:

.. code-block:: php

   $result = $recoveryCodes->consume('user-42', $submittedRecoveryCode);

   if ($result->consumed) {
       // Complete the recovery policy and notify the account owner.
   }

A successful recovery code is consumed by the same atomic mutation that returns
the remaining count. Consider prompting regeneration when few codes remain.
Regeneration replaces every old unused code.

Secret rotation
---------------

``planRotation()`` creates validated enrollment material but does not mutate
application state. A safe flow is:

#. create and persist a pending new generation;
#. show the new enrollment payload;
#. prove possession using the new secret;
#. activate the new generation;
#. optionally accept the old generation until ``overlapUntil``;
#. keep replay IDs separate during overlap; and
#. revoke and erase the old generation at the exclusive boundary.

Account deletion and factor removal
-----------------------------------

Authorize the request independently of the factor being removed. Delete the
encrypted factor secret, its versioned replay state, pending enrollment
material, recovery records when appropriate, and audit references that contain
sensitive payloads. ``GenericOtp::delete()`` only cancels the active generic
challenge for the supplied binding; it is not a user-wide purge operation.

Operational failure behavior
----------------------------

* Invalid constructor or method configuration throws ``InvalidArgumentException``.
* Credential mismatch, malformed code shape, and replay are normal result paths.
* Store/database/network exceptions propagate; authentication code should catch
  them at the application boundary, fail closed, and emit a redacted operational
  event.
* Never retry a non-idempotent verification mutation without knowing whether the
  first transaction committed. Use store-specific idempotency or reconcile state.
