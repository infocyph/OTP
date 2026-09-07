GridOTP API
===========

Service
-------

.. code-block:: php

   new GridOTP(
       AuthenticationStateCacheInterface $cache,
       #[\SensitiveParameter] string $secret,
       int $challengeSize = 6,
       int $ttlSeconds = 120,
       int $maxAttempts = 3,
   );

   public static function generateSecret(int $length = 12): string;

   public static function respond(
       GridChallenge $challenge,
       #[\SensitiveParameter] string $secret,
   ): string;

   public function issue(
       string $factorId,
       ?int $now = null,
   ): GridChallenge;

   public function verify(
       string $factorId,
       GridChallenge $challenge,
       #[\SensitiveParameter] string $response,
       ?int $now = null,
   ): bool;

   public function verifyWithResult(
       string $factorId,
       GridChallenge $challenge,
       #[\SensitiveParameter] string $response,
       ?int $now = null,
   ): VerificationResult;

GridChallenge
-------------

``GridChallenge`` contains the versioned challenge ID, dynamic 32-symbol-to-digit
mapping, ordered requested positions, enrolled secret length, issuance, and
expiration. ``toArray()``/``fromArray()`` support transport and
``canonicalPayload()`` provides the exact challenge representation bound into
CacheLayer state.

Configuration bounds
--------------------

* enrolled secret alphabet: ``ABCDEFGHJKLMNPQRSTUVWXYZ23456789``;
* secret length: 8..32 symbols;
* generated secret default: 12 symbols;
* challenge size: 6..10 distinct positions and never larger than the secret;
* challenge TTL: 1..900 seconds;
* max attempts: 1..10;
* response: decimal digits with length equal to challenge size;
* factor IDs: 1..190 bytes.

GridOTP always requires a coordinated CacheLayer lock because attempts, absolute
expiry, challenge-integrity state, and consumed status are mutated as one
serializable state machine. See :doc:`../guides/grid-otp`.
