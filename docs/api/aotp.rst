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
   ): AotpResponse;

   public function issue(
       AuthenticationStateCacheInterface $cache,
       string $factorId,
       string $context = '',
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

Value objects
-------------

``AotpKeyPair`` contains URL-safe Base64 Ed25519 public/private key material and
redacts the private key in debug output.

``AotpChallenge`` contains the versioned challenge ID, nonce, audience, context,
issuance, and expiration. ``toArray()``/``fromArray()`` support transport and
``signingPayload()`` returns the exact canonical binary payload covered by the
signature.

``AotpResponse`` contains the challenge ID and detached Ed25519 signature and
also supports ``toArray()``/``fromArray()`` transport.

Configuration bounds
--------------------

* factor IDs: 1..190 bytes;
* audience: valid UTF-8, 1..255 bytes;
* context: valid UTF-8, 0..4096 bytes;
* challenge TTL: 1..600 seconds;
* challenge ID: 128 random bits;
* challenge nonce: 256 random bits;
* Ed25519 public key: 32 bytes before URL-safe Base64 encoding;
* Ed25519 private key: 64 bytes before URL-safe Base64 encoding; and
* Ed25519 signature: 64 bytes before URL-safe Base64 encoding.

State behavior
--------------

``issue()`` reserves the complete canonical challenge before returning it.
Successful verification atomically consumes that exact reservation. A duplicate
valid submission is reported as replay. Native CacheLayer atomics are used when
available; otherwise the coordinated lock fallback is used.

AOTP requires a fail-closed, payload-integrity protected, authoritative
CacheLayer authentication-state cache. See :doc:`../guides/aotp` for the
complete enrollment, transport, signing, and verification flow.
