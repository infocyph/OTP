AOTP API
========

Service
-------

.. code-block:: php

   new AOTP(
       string $publicKey,
       string $audience,
   );

   public static function generateKeyPair(): AotpKeyPair;

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
* keys/signatures: fixed Ed25519 sizes encoded as URL-safe Base64 without padding.

AOTP requires a fail-closed, payload-integrity protected, authoritative
CacheLayer authentication-state cache with either native atomics or a
coordinated lock. See :doc:`../guides/aotp`.
