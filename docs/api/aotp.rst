AOTP API
========

``AOTP`` is available only when PHP's ``sodium`` extension is loaded. OTP lists
``ext-sodium`` under Composer ``suggest`` and ``require-dev`` rather than as a
mandatory runtime requirement.

Service
-------

.. code-block:: php

   new AOTP(
       string $publicKey,
       string $audience,
   );

   public static function generateKeyPair(): AotpKeyPair;
   public static function isAvailable(): bool;

   public static function respond(
       #[\SensitiveParameter] string $privateKey,
       AotpChallenge $challenge,
       string $expectedAudience,
       string $expectedContext,
       ?int $now = null,
   ): AotpResponse;

   public function issue(
       AuthenticationStateCacheInterface $cache,
       string $factorId,
       string $context,
       int $ttlSeconds = 120,
       ?int $now = null,
   ): AotpChallenge;

   public function verify(
       AuthenticationStateCacheInterface $cache,
       string $factorId,
       AotpChallenge $challenge,
       AotpResponse $response,
       ?int $now = null,
   ): bool;

   public function verifyWithResult(
       AuthenticationStateCacheInterface $cache,
       string $factorId,
       AotpChallenge $challenge,
       AotpResponse $response,
       ?int $now = null,
   ): VerificationResult;

``generateKeyPair()`` and ``respond()`` throw ``LogicException`` when sodium is
not available. The constructor also fails immediately when AOTP cannot be used.
The verifier constructor accepts only the public key; the private key belongs on
the client/device.

``respond()`` is intentionally misuse-resistant. It requires independent
``expectedAudience`` and ``expectedContext`` values and refuses to sign when
either differs from the received challenge. It also refuses a challenge before
``issuedAt`` or at/after ``expiresAt``. The optional ``now`` parameter exists for
deterministic testing/integration clocks; production callers normally omit it.

The expected values must come from trusted client configuration/local operation
state. Passing ``$challenge->audience`` or ``$challenge->context`` back as the
expected values defeats the protection against verifier/context confusion.

Value objects
-------------

``AotpKeyPair`` contains URL-safe Base64 Ed25519 public/private key material and
redacts the private key in debug output.

``AotpChallenge`` contains the versioned challenge ID, nonce, audience, mandatory
context, issuance, and expiration. ``toArray()``/``fromArray()`` support
transport and ``signingPayload()`` returns the exact canonical binary payload
covered by the signature. Challenge debug output redacts nonce and context.

``AotpResponse`` contains the challenge ID and detached Ed25519 signature and
also supports ``toArray()``/``fromArray()`` transport.

Configuration bounds
--------------------

* factor IDs: 1..190 bytes;
* audience: valid UTF-8, 1..255 bytes, without whitespace/control characters;
* context: valid UTF-8, 1..4096 bytes, without control characters;
* challenge TTL: 1..600 seconds;
* challenge ID: 128 random bits;
* challenge nonce: 256 random bits;
* Ed25519 public key: 32 bytes before URL-safe Base64 encoding;
* Ed25519 private key: 64 bytes before URL-safe Base64 encoding; and
* Ed25519 signature: 64 bytes before URL-safe Base64 encoding.

Audience/context comparisons are exact byte comparisons. OTP does not normalize
hostnames, URLs, Unicode, case, or application transaction data.

State behavior
--------------

``issue()`` reserves the complete canonical challenge before returning it.
Successful verification atomically consumes that exact reservation. A duplicate
submission from a valid signer is reported as replay. Native CacheLayer atomics
are used when available; otherwise the coordinated lock fallback is used.

Signature validity is checked before consumed-state replay is returned. A party
that cannot produce a valid signature therefore receives ``Mismatch`` rather
than learning whether the challenge has already been consumed.

AOTP requires a fail-closed, payload-integrity protected, authoritative
CacheLayer authentication-state cache.

Security boundary
-----------------

AOTP proves possession of the enrolled Ed25519 private key and enforces one-time
challenge acceptance. It does not by itself prove that the user is interacting
directly with the intended service. Phishing/relay resistance requires an
end-to-end client/verifier design where the client independently authenticates
the verifier and derives the expected context from trusted local
session/transaction state.

See :doc:`../guides/aotp` for the complete enrollment, transport, signing,
verification, relay-threat, and deployment flow.
