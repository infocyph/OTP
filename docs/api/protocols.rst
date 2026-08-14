Protocol API
============

This page lists every public method on the main service classes. Named arguments
are shown throughout the guides and are recommended for calls with several
optional values.

GenericOtp
----------

Constructor:

.. code-block:: php

   new GenericOtp(
       AuthenticationStateCacheInterface $cache,
       #[\SensitiveParameter] string $key,
       int $digits = 6,
       int $ttlSeconds = 300,
       int $maxAttempts = 3,
   );

Methods:

.. code-block:: php

   public function generate(string $binding): string;
   public function verify(string $binding, string $otp): bool;
   public function delete(string $binding): bool;

``generate()`` returns plaintext only after the locked CacheLayer write succeeds.
``verify()`` consumes on success or decrements a well-shaped mismatch.
``delete()`` cancels the single binding. Cache and lock failures throw. The cache
must pass the authentication-state policy described in :doc:`contracts`. See
:doc:`../guides/generic-otp`.

HOTP
----

Constructor and secret generation:

.. code-block:: php

   new HOTP(
       #[\SensitiveParameter] string $secret,
       int $digits = 6,
       string $algorithm = 'sha1',
   );

   public static function generateSecret(int $bytes = 20): string;

Calculation:

.. code-block:: php

   public function generate(int $counter): string;

Verification:

.. code-block:: php

   public function verify(
       string $otp,
       int $counter,
       int $lookAhead = 0,
   ): bool;

   public function verifyWithResult(
       string $otp,
       int $counter,
       int $lookAhead = 0,
       ?AuthenticationStateCacheInterface $cache = null,
       ?string $factorId = null,
   ): VerificationResult;

Enrollment:

.. code-block:: php

   public function getProvisioningUri(
       string $label,
       string $issuer,
       int $initialCounter = 0,
       array $additionalParameters = [],
   ): string;

   public function getProvisioningUriQR(
       string $label,
       string $issuer,
       int $initialCounter = 0,
       array $additionalParameters = [],
       int $imageSize = 200,
   ): string;

   public function getEnrollmentPayload(
       string $label,
       string $issuer,
       int $initialCounter = 0,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): EnrollmentPayload;

Rotation:

.. code-block:: php

   public function planRotation(
       string $newSecret,
       string $label,
       string $issuer,
       int $initialCounter = 0,
       ?int $gracePeriodInSeconds = null,
       ?int $now = null,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): SecretRotation;

See :doc:`../guides/hotp` and :doc:`../guides/secret-rotation`.

TOTP
----

Constructor and secret generation:

.. code-block:: php

   new TOTP(
       #[\SensitiveParameter] string $secret,
       int $digits = 6,
       int $period = 30,
       string $algorithm = 'sha1',
   );

   public static function generateSecret(int $bytes = 20): string;

Calculation and time helpers:

.. code-block:: php

   public function generate(?int $timestamp = null): string;
   public function getCurrentTimeStep(?int $timestamp = null): int;
   public function getTimeStepFromTimestamp(int $timestamp): int;
   public function getRemainingSeconds(?int $timestamp = null): int;

Verification:

.. code-block:: php

   public function verify(
       string $otp,
       ?int $timestamp = null,
       int $pastWindows = 0,
       int $futureWindows = 0,
   ): bool;

   public function verifyWithWindow(
       string $otp,
       ?int $timestamp = null,
       ?VerificationWindow $window = null,
       ?AuthenticationStateCacheInterface $cache = null,
       ?string $factorId = null,
   ): VerificationResult;

Enrollment:

.. code-block:: php

   public function getProvisioningUri(
       string $label,
       string $issuer,
       array $additionalParameters = [],
   ): string;

   public function getProvisioningUriQR(
       string $label,
       string $issuer,
       array $additionalParameters = [],
       int $imageSize = 200,
   ): string;

   public function getEnrollmentPayload(
       string $label,
       string $issuer,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): EnrollmentPayload;

Rotation:

.. code-block:: php

   public function planRotation(
       string $newSecret,
       string $label,
       string $issuer,
       ?int $gracePeriodInSeconds = null,
       ?int $now = null,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): SecretRotation;

See :doc:`../guides/totp`.

OCRA
----

Key creation and suite inspection:

.. code-block:: php

   new OCRA(
       string $suite,
       #[\SensitiveParameter] string $sharedKey,
   );

   public static function fromBase32(
       string $suite,
       string $secret,
   ): self;

   public static function generateSecret(int $bytes = 20): string;
   public static function sessionHex(string $hex): string;
   public function getSuite(): OcraSuite;

``sessionHex()`` decodes a hexadecimal representation of valid UTF-8 session
data. It rejects decoded arbitrary binary that is not valid UTF-8.

Generation:

.. code-block:: php

   public function generate(
       string $challenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
   ): string;

   public function generateMutual(
       string $clientChallenge,
       string $serverChallenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
   ): string;

   public function generateSignature(
       string $signatureChallenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
   ): string;

Verification:

.. code-block:: php

   public function verify(
       string $otp,
       string $challenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
       ?VerificationWindow $timeWindow = null,
   ): bool;

   public function verifyMutual(
       string $otp,
       string $clientChallenge,
       string $serverChallenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
       ?VerificationWindow $timeWindow = null,
   ): bool;

   public function verifyWithResult(
       string $otp,
       string $challenge,
       ?int $counter = null,
       ?string $pin = null,
       ?string $session = null,
       ?int $timestamp = null,
       ?VerificationWindow $timeWindow = null,
       ?AuthenticationStateCacheInterface $cache = null,
       ?string $factorId = null,
       ?int $replayTtl = null,
   ): VerificationResult;

``verifyMutual()`` is boolean-only and does not accept package replay storage.
Fresh server-challenge consumption belongs to the application.

Enrollment:

.. code-block:: php

   public function getProvisioningUri(
       string $label,
       string $issuer,
       array $additionalParameters = [],
   ): string;

   public function getProvisioningUriQR(
       string $label,
       string $issuer,
       array $additionalParameters = [],
       int $imageSize = 200,
   ): string;

   public function getEnrollmentPayload(
       string $label,
       string $issuer,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): EnrollmentPayload;

Rotation:

.. code-block:: php

   public function planRotation(
       string $newSecret,
       string $label,
       string $issuer,
       ?int $gracePeriodInSeconds = null,
       ?int $now = null,
       array $additionalParameters = [],
       bool $withQrSvg = false,
       int $imageSize = 200,
   ): SecretRotation;

See :doc:`../guides/ocra`.

RecoveryCodes
-------------

Constructor:

.. code-block:: php

   new RecoveryCodes(
       RecoveryCodeStoreInterface $store,
       #[\SensitiveParameter] string $key,
   );

Generation:

.. code-block:: php

   public function generate(
       string $binding,
       int $count = 10,
       int $length = 12,
       int $groupSize = 4,
       string $characterSet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
   ): RecoveryCodeGenerationResult;

Consumption:

.. code-block:: php

   public function consume(
       string $binding,
       #[\SensitiveParameter] string $code,
   ): RecoveryCodeConsumptionResult;

Generation replaces the entire active batch. Consumption is normalization-aware,
atomic, and single use. See :doc:`../guides/recovery-codes`.

Argument and exception conventions
----------------------------------

* Secret, key, PIN, session, and submitted credential parameters are sensitive.
* Optional timestamps use current Unix time when null.
* Method configuration is validated before credential shape.
* Invalid configuration/protocol input throws ``InvalidArgumentException``.
* Normal credential failure returns false or a detailed result.
* Store exceptions propagate.
