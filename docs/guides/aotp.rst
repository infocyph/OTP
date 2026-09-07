AOTP
====

``AOTP`` is Infocyph's asymmetric one-time challenge-response primitive. It is
not an RFC-defined OTP algorithm and is not compatible with ``otpauth://``
authenticator applications.

The verifier stores an Ed25519 public key. The client holds the corresponding
private key and signs a short-lived server-issued challenge. A successful
challenge is consumed exactly once through CacheLayer.

Requirements
------------

AOTP is optional and requires PHP's ``sodium`` extension. The extension is
listed under Composer ``suggest`` and ``require-dev`` rather than as a mandatory
runtime dependency, so applications that do not use AOTP do not need sodium.
Check capability before exposing AOTP enrollment or authentication:

.. code-block:: php

   use Infocyph\OTP\AOTP;

   if (!AOTP::isAvailable()) {
       throw new RuntimeException('AOTP requires ext-sodium.');
   }

The verifier also needs a fail-closed, payload-integrity protected,
authoritative CacheLayer authentication-state cache. Native atomic state is used
when the configured backend supports it; otherwise CacheLayer's coordinated lock
fallback is used.

Security properties
-------------------

The signed challenge binds a 128-bit random challenge ID, a 256-bit random
nonce, verifier audience, optional context, issuance time, and expiration time.
The CacheLayer reservation key is derived from the complete canonical challenge,
not only its ID, so modified context or timestamps cannot reuse issued state.

AOTP uses Ed25519 from ``ext-sodium``. It does not implement RSA, ECDSA,
signature truncation, or a numeric-only proof mode.

Complete enrollment and authentication flow
-------------------------------------------

The following example shows both roles. In a real deployment the client and
verifier run on different systems. ``$stateCache`` is the shared authentication
state cache configured as described in :doc:`storage`.

Enrollment starts on the client. Generate a key pair once for the factor and
keep the private key only on the client/device:

.. code-block:: php

   use Infocyph\OTP\AOTP;

   $keys = AOTP::generateKeyPair();

   // Client/device storage. Prefer hardware-backed or encrypted storage.
   $clientPrivateKey = $keys->privateKey;

   // Send only this value to the verifier over an authenticated enrollment flow.
   $publicKeyForServer = $keys->publicKey;

Persist the public key with a generation-specific factor identifier. Rotating the
key pair must create a new factor generation:

.. code-block:: php

   $factorId = 'user-42:aotp:key-v1';
   $audience = 'login.example.com';

   // Application database fields, shown conceptually:
   persistAotpFactor(
       factorId: $factorId,
       publicKey: $publicKeyForServer,
       audience: $audience,
   );

When authentication starts, the verifier loads the public key and issues a
short-lived challenge. ``context`` should identify the intended operation when
that distinction matters:

.. code-block:: php

   use Infocyph\OTP\AOTP;

   $factor = loadAotpFactor('user-42:aotp:key-v1');
   $aotp = new AOTP($factor->publicKey, $factor->audience);

   $challenge = $aotp->issue(
       cache: $stateCache,
       factorId: $factor->factorId,
       context: 'login:web',
       ttlSeconds: 120,
   );

   $challengeJson = json_encode(
       $challenge->toArray(),
       JSON_THROW_ON_ERROR,
   );

Send ``$challengeJson`` to the client. The client reconstructs the value object,
verifies the expected audience from trusted local configuration, optionally
checks the human-visible context, then signs:

.. code-block:: php

   use Infocyph\OTP\AOTP;
   use Infocyph\OTP\ValueObjects\AotpChallenge;

   $challenge = AotpChallenge::fromArray(
       json_decode($challengeJson, true, 512, JSON_THROW_ON_ERROR),
   );

   $response = AOTP::respond(
       privateKey: $clientPrivateKey,
       challenge: $challenge,
       expectedAudience: 'login.example.com',
   );

   $responseJson = json_encode(
       $response->toArray(),
       JSON_THROW_ON_ERROR,
   );

The explicit ``expectedAudience`` argument is intentional. It must come from
independently trusted client configuration, not simply from the challenge.

The client returns the challenge and response. Returning the challenge is safe:
the server reservation is derived from its complete canonical payload and the
signature covers the same payload, so modified challenge fields fail closed.
The verifier reconstructs both values and performs the one-time verification:

.. code-block:: php

   use Infocyph\OTP\ValueObjects\AotpChallenge;
   use Infocyph\OTP\ValueObjects\AotpResponse;
   use Infocyph\OTP\VerificationReason;

   $submittedChallenge = AotpChallenge::fromArray(
       json_decode($submittedChallengeJson, true, 512, JSON_THROW_ON_ERROR),
   );
   $submittedResponse = AotpResponse::fromArray(
       json_decode($responseJson, true, 512, JSON_THROW_ON_ERROR),
   );

   $result = $aotp->verifyWithResult(
       cache: $stateCache,
       factorId: $factor->factorId,
       challenge: $submittedChallenge,
       response: $submittedResponse,
   );

   if ($result->matched) {
       // Complete the application's authenticated session transition.
   } elseif ($result->reason === VerificationReason::Replay) {
       // The issued challenge was already consumed. Fail closed.
   } else {
       // Invalid, expired, tampered, or incorrectly signed challenge/response.
   }

Use ``verify()`` only when a boolean result is sufficient. ``verifyWithResult()``
is preferred at authentication boundaries because it preserves replay status for
internal policy and audit without requiring the public response to expose that
detail.

State and replay behavior
-------------------------

``issue()`` reserves the exact canonical challenge before returning it. If the
state write fails, no usable challenge is returned. After a valid signature,
verification atomically transitions the reservation from ``0`` to ``1``.
Concurrent valid submissions therefore have exactly one successful consumer.
The consumed marker remains until the original challenge expiry so duplicates
can be reported as ``VerificationReason::Replay``.

AOTP uses native CacheLayer atomics when available. Backends without atomics use
the coordinated lock fallback. A selected atomic mutation is not retried through
the lock path after an exception because the commit outcome could be unknown.

Operational rules
-----------------

* Store only the public key at the verifier.
* Protect the client private key with the strongest storage available.
* Use a factor ID tied to the exact key generation.
* Keep challenge TTLs short.
* Use a stable, trusted verifier audience and validate it on the client.
* Bind transaction/login intent into ``context`` when confusion between
  operations would matter.
* Rate-limit enrollment, challenge issuance, and verification endpoints even
  though Ed25519 signatures are not short guessable OTPs.
* Do not log private keys, challenge nonces/context, or signatures.

Do not advertise generic AOTP as phishing resistant automatically. A relay can
proxy a live challenge unless the client independently knows and enforces the
intended verifier and, where relevant, verifies the transaction context before
signing.
