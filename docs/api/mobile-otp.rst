MobileOTP API
=============

Constructor and secret generation:

.. code-block:: php

   new MobileOTP(
       #[\SensitiveParameter] string $secret,
       #[\SensitiveParameter] string $pin,
   );

   public static function generateSecret(): string;

Generation and time:

.. code-block:: php

   public function generate(
       ?int $timestamp = null,
       int $offsetSteps = 0,
   ): string;

   public function getTimeStepFromTimestamp(
       int $timestamp,
       int $offsetSteps = 0,
   ): int;

Verification:

.. code-block:: php

   public function verify(
       string $otp,
       ?int $timestamp = null,
       int $pastWindows = 0,
       int $futureWindows = 0,
       int $offsetSteps = 0,
   ): bool;

   public function verifyWithWindow(
       string $otp,
       ?int $timestamp = null,
       ?VerificationWindow $window = null,
       int $offsetSteps = 0,
       ?AuthenticationStateCacheInterface $cache = null,
       ?string $factorId = null,
   ): VerificationResult;

``PERIOD`` is 10 seconds and ``OUTPUT_LENGTH`` is six hexadecimal characters.
Verification windows are capped at the legacy three-minute/18-step tolerance per
direction. ``offsetSteps`` is a fixed clock offset and is not reported as drift.

See :doc:`../guides/mobile-otp`.
