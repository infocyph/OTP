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
nonce, verifier audience, mandatory operation/session context, issuance time,
and expiration time. The CacheLayer reservation key is derived from the complete
canonical challenge, not only its ID, so modified context or timestamps cannot
reuse issued state.

AOTP uses Ed25519 from ``ext-sodium``. It does not implement RSA, ECDSA,
signature truncation, or a numeric-only proof mode. Binary private-key copies
created internally for signing are cleared with ``sodium_memzero()`` after use.
The caller still owns the original encoded private-key string and must protect
its lifetime and storage.

Audience and context are compared as exact UTF-8 byte strings. OTP performs no
Unicode normalization, case folding, hostname rewriting, URL normalization, or
context interpretation. Audience values cannot contain whitespace/control
characters; contexts cannot be empty or contain control characters.

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

   persistAotpFactor(
       factorId: $factorId,
       publicKey: $publicKeyForServer,
       audience: $audience,
   );

When authentication starts, the verifier loads the public key and creates a
fresh flow/session identifier. The context is mandatory and should bind the
operation to that flow rather than using a generic constant such as ``login``:

.. code-block:: php

   use Infocyph\OTP\AOTP;

   $factor = loadAotpFactor('user-42:aotp:key-v1');
   $aotp = new AOTP($factor->publicKey, $factor->audience);

   $flowId = bin2hex(random_bytes(16));
   $context = 'login:web:' . $flowId;

   // Persist/bind $flowId to the authenticated pre-login flow.
   persistPendingLoginFlow($flowId, $factor->factorId);

   $challenge = $aotp->issue(
       cache: $stateCache,
       factorId: $factor->factorId,
       context: $context,
       ttlSeconds: 120,
   );

   $challengeJson = json_encode(
       $challenge->toArray(),
       JSON_THROW_ON_ERROR,
   );

Send ``$challengeJson`` to the client. The client reconstructs the challenge but
must not trust its audience/context merely because they arrived inside the
challenge. Both expected values must come from independent trusted client state.
For example, a dedicated client can have the verifier audience pinned in
configuration and know which locally initiated login/transaction flow it is
currently authorizing:

.. code-block:: php

   use Infocyph\OTP\AOTP;
   use Infocyph\OTP\ValueObjects\AotpChallenge;

   $challenge = AotpChallenge::fromArray(
       json_decode($challengeJson, true, 512, JSON_THROW_ON_ERROR),
   );

   // Trusted local configuration / locally initiated operation state.
   $expectedAudience = 'login.example.com';
   $expectedContext = 'login:web:' . $locallyKnownFlowId;

   $response = AOTP::respond(
       privateKey: $clientPrivateKey,
       challenge: $challenge,
       expectedAudience: $expectedAudience,
       expectedContext: $expectedContext,
   );

   $responseJson = json_encode(
       $response->toArray(),
       JSON_THROW_ON_ERROR,
   );

``respond()`` refuses to sign when audience or context differs from the client's
independently expected value. It also refuses a challenge before ``issuedAt`` or
at/after ``expiresAt``. Clients therefore need a trustworthy local clock; do not
work around clock problems by blindly widening or skipping lifetime checks.

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
       consumePendingLoginFlow($flowId);
       // Complete the application's authenticated session transition.
   } elseif ($result->reason === VerificationReason::Replay) {
       // The issued challenge was already consumed by a valid signer. Fail closed.
   } else {
       // Invalid, expired, tampered, incorrectly signed, or wrong-flow response.
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
from a valid signer can be reported as ``VerificationReason::Replay``.

AOTP verifies the signature before exposing replay state. An invalid signer gets
``Mismatch`` even when the same challenge was already consumed, preventing the
replay marker from becoming a state oracle for parties that cannot produce a
valid signature.

AOTP uses native CacheLayer atomics when available. Backends without atomics use
the coordinated lock fallback. A selected atomic mutation is not retried through
the lock path after an exception because the commit outcome could be unknown.

Phishing and relay resistance
-----------------------------

AOTP provides asymmetric proof-of-possession and replay-resistant challenge
authentication. **Phishing resistance is an end-to-end property of the consuming
client and verifier.** The client must independently authenticate the intended
verifier and bind signing to trusted local session/transaction context rather
than blindly signing received challenges.

AOTP alone cannot stop a real-time relay like this:

.. code-block:: text

   victim client       phishing relay        real verifier
        |                    |                    |
        |                    |--- start -------->|
        |                    |<-- challenge -----|
        |<-- challenge ------|                    |
        |--- signature ----->|                    |
        |                    |--- signature ---->|

The relayed challenge may contain the genuine audience and genuine server
signature input. If the client merely copies ``challenge.audience`` and
``challenge.context`` into its expected values, all AOTP checks still succeed and
the attacker can relay the valid proof.

Therefore:

* ``expectedAudience`` must come from pinned/trusted client configuration, never
  from ``$challenge->audience``;
* ``expectedContext`` must come from a locally known operation/session/transaction
  state, never from ``$challenge->context``;
* context should include a fresh flow/transaction identifier, not merely
  ``login`` or ``approve``;
* when transaction details matter, the client must display/derive the same
  canonical details that are represented by the expected context before signing;
* a client that cannot independently determine verifier + context must treat
  AOTP as proof-of-possession/replay protection, **not phishing-resistant auth**;
* prefer Passkey/WebAuthn when browser-origin-bound phishing resistance is the
  goal, because the browser/authenticator enforce RP/origin relationships that a
  generic AOTP transport cannot enforce itself.

Do not market or document an integration as phishing-resistant merely because it
uses Ed25519, an audience field, or a signed context. Those are necessary
building blocks; the surrounding trusted client/verifier protocol determines the
property.

Operational rules
-----------------

* Store only the public key at the verifier.
* Protect the client private key with the strongest storage available.
* Use a factor ID tied to the exact key generation.
* Keep challenge TTLs short and keep client/verifier clocks trustworthy.
* Use a stable, pinned verifier audience and validate it independently on the
  client.
* Always use a non-empty context and bind it to a fresh locally known login,
  session, or transaction flow.
* Never construct ``expectedAudience`` or ``expectedContext`` by echoing fields
  from the received challenge.
* Canonicalize business context in the application before both sides derive the
  expected value; do not sign ambiguous display text.
* Rate-limit enrollment, challenge issuance, and verification endpoints even
  though Ed25519 signatures are not short guessable OTPs.
* Do not log private keys, challenge nonces/context, or signatures.
* Rotate/revoke the factor immediately after suspected private-key compromise.
