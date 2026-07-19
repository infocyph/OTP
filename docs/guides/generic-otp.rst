Generic OTP Guide
=================

Generic OTP is useful when you want one-time codes without managing a dedicated OTP database table, while still keeping server-side verification state.

It is a strong fit for delivery channels such as SMS, email, and instant messaging platforms, because your application generates the code and decides how to deliver it.

When to use it
--------------

This mode is application-oriented rather than RFC-specific. That does not limit it to any one transport. It is useful for cases like:

- signup verification
- SMS OTP
- email OTP
- OTP over chat or IM platforms
- password reset codes
- short-lived step-up verification codes

PSR-6 cache requirement
-----------------------

The generic OTP class requires a PSR-6 cache pool implementation:

.. code-block:: php

   <?php
   use Infocyph\OTP\OTP;

   $otp = new OTP(
       digitCount: 6,
       validUpto: 60,
       retry: 3,
       hashAlgorithm: 'sha256',
       cacheAdapter: $cachePool,
       hashKey: $applicationOtpKey,
   );

Codes are strings
-----------------

- Generated codes are strings.
- Verification expects a string.
- Leading zeroes are preserved.

Basic flow
----------

.. code-block:: php

   <?php
   $code = $otp->generate('signup:alice@example.com');
   $otp->verify('signup:alice@example.com', $code);
   $otp->delete('signup:alice@example.com');

Another example for a password reset flow:

.. code-block:: php

   <?php
   $signature = 'password-reset:user-42';
   $code = $otp->generate($signature);

   // deliver $code to the user

   if ($otp->verify($signature, $submittedCode)) {
       // continue reset flow
   }

Example for SMS or IM delivery:

.. code-block:: php

   <?php
   $signature = 'login-otp:user-42:phone:+15551234567';
   $code = $otp->generate($signature);

   // send $code by SMS, WhatsApp, Telegram, or another messaging channel

   if ($otp->verify($signature, $submittedCode)) {
       // mark the login challenge as verified
   }

Retry semantics
---------------

The third argument of ``verify()`` controls whether a found record should be removed immediately:

.. code-block:: php

   <?php
   $otp->verify('signup:alice@example.com', $code, deleteIfFound: false);

When ``deleteIfFound`` is ``false``, the record remains until it is verified, runs out of retries, or expires.

Data model
----------

The generic OTP cache payload keeps:

- a hashed representation of the generated OTP
- retry state
- the expiration moment

Because codes are strings, leading zeroes are preserved correctly.

Security and limits
-------------------

- SHA-256 is the default stored-code digest; SHA-512 is also supported.
- For production, provide a purpose-specific ``hashKey`` of at least 16 random bytes and keep it outside the OTP cache.
- Non-cryptographic hashes are rejected because OTP verification is an authentication decision.
- Signature cache keys use SHA-256 to prevent attacker-controlled non-cryptographic collisions.
- Configuration is validated when the immutable OTP instance is constructed.
- Validity is bounded to 86400 seconds, retries to 100, and signature input to 4096 bytes.
- PSR-6 does not define an atomic consume operation. Use a cache/storage integration with an application-level atomic consume when concurrent verification of the same generic OTP must be prevented.
