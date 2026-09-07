Application workflows
=====================

The library exposes cryptographic/protocol and atomic-storage primitives. This
guide shows how they fit into complete application scenarios. The dedicated
protocol guides contain the full parameter and transport details.

Authenticator-app enrollment
----------------------------

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

See :doc:`totp` and :doc:`provisioning`.

OTP login verification
----------------------

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
capability is unavailable.

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
binding replaces the old code. See :doc:`generic-otp`.

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
range of acceptable token state; the package caps look-ahead at 100. See
:doc:`hotp`.

OCRA challenge-response
-----------------------

OCRA is appropriate when the response must authenticate explicit challenge,
counter, PIN/session, or time inputs defined by an RFC 6287 suite. The
application still owns challenge freshness and transaction authorization.

.. code-block:: php

   $result = $ocra->verifyWithResult(
       otp: $submittedResponse,
       challenge: $serverChallenge,
       counter: $counter,
       cache: $stateCache,
       factorId: 'merchant-9:ocra:key-v3',
   );

Do not display one transaction while signing different bytes. See :doc:`ocra`
for mutual challenge and transaction-signature examples.

AOTP enrollment and login
-------------------------

AOTP is an optional public-key challenge-response flow. It requires
``ext-sodium``. Generate the Ed25519 key pair on the client/device where possible,
persist only the public key at the verifier, and assign a key-generation-specific
factor ID.

.. code-block:: php

   use Infocyph\OTP\AOTP;

   $keys = AOTP::generateKeyPair();

   // Client keeps $keys->privateKey.
   persistAotpPublicKey('user-42:aotp:key-v1', $keys->publicKey);

For login, the verifier creates a fresh application flow ID and binds it into the
mandatory AOTP context:

.. code-block:: php

   $aotp = new AOTP($storedPublicKey, 'login.example.com');
   $flowId = bin2hex(random_bytes(16));
   $context = 'login:web:' . $flowId;

   persistPendingLoginFlow($flowId, 'user-42:aotp:key-v1');

   $challenge = $aotp->issue(
       $stateCache,
       'user-42:aotp:key-v1',
       context: $context,
   );

The client signs only when both verifier and operation match independently
trusted local state. Never populate expected values by copying fields from the
received challenge:

.. code-block:: php

   // Client side: trusted configuration/local operation state.
   $response = AOTP::respond(
       $clientPrivateKey,
       $challenge,
       expectedAudience: 'login.example.com',
       expectedContext: 'login:web:' . $locallyKnownFlowId,
   );

   // Verifier side:
   $result = $aotp->verifyWithResult(
       $stateCache,
       'user-42:aotp:key-v1',
       $challenge,
       $response,
   );

   if ($result->matched) {
       consumePendingLoginFlow($flowId);
       // Complete the intended session transition.
   }

The issued challenge is server-reserved and consumed exactly once.
``AOTP::respond()`` refuses a wrong audience/context and refuses future/expired
challenges before signing. AOTP provides asymmetric proof-of-possession and
replay-resistant challenge authentication, but phishing resistance requires the
surrounding client/verifier design to independently authenticate the verifier and
derive expected context from trusted local session/transaction state. See
:doc:`aotp` for the full relay-threat model and transport scenario.

GridOTP enrollment and login
----------------------------

GridOTP enrolls a human knowledge secret and never asks the user to submit that
secret directly during login.

.. code-block:: php

   use Infocyph\OTP\GridOTP;

   $secret = GridOTP::generateSecret();
   persistEncryptedGridSecret('user-42:grid:secret-v1', $secret);

   $gridOtp = new GridOTP($stateCache, $secret);
   $challenge = $gridOtp->issue('user-42:grid:secret-v1');

The UI renders the challenge grid and requested positions. It submits only the
mapped decimal response. The verifier uses the returned challenge plus response:

.. code-block:: php

   $result = $gridOtp->verifyWithResult(
       'user-42:grid:secret-v1',
       $submittedChallenge,
       $submittedResponse,
   );

GridOTP's attempt counter, integrity digest, expiry, and consumed state mutate
under one CacheLayer lock. It reduces direct secret/keylogger exposure but is not
shoulder-surfing proof. See :doc:`grid-otp`.

MobileOTP legacy interoperability
---------------------------------

Use MobileOTP only when an existing mOTP deployment requires its 10-second,
Init-Secret + four-digit PIN + MD5 wire calculation.

.. code-block:: php

   use Infocyph\OTP\MobileOTP;

   $mobile = new MobileOTP(
       secret: $storedInitSecret,
       pin: $storedPin,
   );

   $result = $mobile->verifyWithWindow(
       otp: $submittedOtp,
       cache: $stateCache,
       factorId: 'user-42:mobile:secret-v1',
   );

Encrypt both Init-Secret and PIN, preserve Init-Secret character case, keep the
acceptance window as small as possible, and use monitored time synchronization.
See :doc:`mobile-otp` for legacy window and fixed-offset handling.

Passkey registration
--------------------

Passkey is an optional wrapper around ``web-auth/webauthn-lib``. The application
starts the registration ceremony server-side, sends ``optionsJson`` and ceremony
ID to the browser, and returns the browser credential to
``finishRegistration()``.

.. code-block:: php

   use Infocyph\OTP\Passkey;

   $passkey = new Passkey(
       cache: $stateCache,
       rpId: 'example.com',
       allowedOrigins: ['https://example.com'],
   );

   $binding = 'user-42:passkey:registration:flow-7f2c';
   $ceremony = $passkey->beginRegistration(
       binding: $binding,
       userHandle: 'user-42',
       username: 'alice@example.com',
       displayName: 'Alice',
   );

   $result = $passkey->finishRegistration(
       binding: $binding,
       ceremonyId: $submittedCeremonyId,
       credentialJson: $browserCredentialJson,
   );

   if ($result->matched) {
       persistCredentialRecord(
           $result->credentialId,
           $result->credentialRecordJson,
       );
   }

The authenticator owns the private key. OTP stores only the short-lived ceremony
in CacheLayer; the application stores ``CredentialRecord`` durably. See
:doc:`passkey` for complete JavaScript and PHP registration code.

Passkey authentication
----------------------

Account-bound login passes the user's stored records to
``beginAuthentication()``. Discoverable/usernameless login can start without a
record list, then use ``extractCredentialId()`` only to locate the durable record
before full validation.

.. code-block:: php

   $ceremony = $passkey->beginAuthentication('login-flow-9af3');
   $credentialId = $passkey->extractCredentialId($browserCredentialJson);
   $stored = loadCredentialRecord($credentialId);

   $result = $passkey->finishAuthentication(
       binding: 'login-flow-9af3',
       ceremonyId: $submittedCeremonyId,
       credentialRecordJson: $stored->recordJson,
       credentialJson: $browserCredentialJson,
   );

   if ($result->matched) {
       // Persist counter/backup/UV changes before completing the session.
       updateCredentialRecord($result->credentialId, $result->credentialRecordJson);
   }

Never treat ``extractCredentialId()`` as authentication. Reject revoked records
before completing the session. Successful ceremonies are marked consumed until
their original expiry. See :doc:`passkey`.

Recovery-code fallback
----------------------

Recovery should be a distinct, strongly controlled route:

.. code-block:: php

   $result = $recoveryCodes->consume('user-42', $submittedRecoveryCode);

   if ($result->consumed) {
       // Complete the recovery policy and notify the account owner.
   }

A successful recovery code is consumed by the same atomic mutation that returns
the remaining count. Consider prompting regeneration when few codes remain.
Regeneration replaces every old unused code. See :doc:`recovery-codes`.

Secret and factor rotation
--------------------------

``planRotation()`` covers HOTP/TOTP/OCRA enrollment material but does not mutate
application state. A safe general flow is:

#. create and persist a pending new generation;
#. show/provision the new enrollment material or public-key association;
#. prove possession using the new generation;
#. activate the new generation;
#. optionally accept the old generation through a defined overlap;
#. keep replay/factor IDs separate during overlap; and
#. revoke and erase the old generation at the exclusive boundary.

AOTP key rotation, GridOTP secret rotation, and MobileOTP secret/PIN rotation
must likewise receive new generation-specific factor IDs. Passkey credential
rotation is application-owned registration/revocation rather than OTP secret
rotation.

Account deletion and factor removal
-----------------------------------

Authorize the request independently of the factor being removed. Delete
application-owned factor secrets/public keys/Passkey CredentialRecords and any
state that should not survive the account. ``GenericOtp::delete()`` only cancels
the active generic challenge for the supplied binding; it is not a user-wide
purge operation. Avoid broad cache namespace flushes that could affect other
active authentication flows.

Operational failure behavior
----------------------------

* Invalid constructor or method configuration throws ``InvalidArgumentException``.
* Missing optional AOTP/Passkey capability throws ``LogicException``.
* Credential mismatch, malformed input, and replay are normal result paths.
* Store/database/network exceptions propagate; authentication code should catch
  them at the application boundary, fail closed, and emit a redacted operational
  event.
* Never retry a non-idempotent verification mutation without knowing whether the
  first transaction committed. Use store-specific idempotency or reconcile state.

After any successful authentication method, rotate the application session or
otherwise perform the intended authenticated state transition atomically enough
that a pre-authentication session cannot be reused.
