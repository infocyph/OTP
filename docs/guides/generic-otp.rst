Generic OTP
===========

.. code-block:: php

   $otp = new \Infocyph\OTP\GenericOtp(
       store: $atomicStore,
       key: $genericOtpKey,
       digits: 6,
       ttlSeconds: 300,
       maxAttempts: 3,
   );
   $code = $otp->generate($challengeBinding);
   $valid = $otp->verify($challengeBinding, $submittedCode);

Issue atomically replaces an existing challenge. Success consumes it. A validly
shaped mismatch decrements attempts, deleting at zero, while preserving the
original absolute expiration. Malformed codes do not consume attempts.
HMAC-SHA-256 binds ``generic-otp``, the challenge, and code. There is no unkeyed
mode, PSR-6 fallback, bulk flush, or delete-on-any-attempt option.

Applications own code delivery, resend cooldowns, throttling, and enumeration
policy.
