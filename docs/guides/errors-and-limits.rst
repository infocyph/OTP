Errors, results, and limits
===========================

The API distinguishes programmer/configuration errors from normal credential
failure.

Exceptions
----------

Invalid configuration or protocol input throws ``InvalidArgumentException``.
Examples include weak secrets, unsupported algorithms, negative timestamps,
invalid OCRA suites, missing suite-required inputs, invalid provisioning URIs,
and cache/factor-ID mismatches or unsafe authentication-state caches.

Storage and runtime failures propagate their original exception. Catch them at
the application boundary, fail closed, and avoid sensitive log context.

Normal verification failure
---------------------------

Boolean methods return ``false``. Detailed HOTP, TOTP, and OCRA methods return a
``VerificationResult`` with one of:

* ``Malformed`` — wrong credential width or character class;
* ``Mismatch`` — valid shape but no cryptographic candidate matched; or
* ``Replay`` — cryptographic match rejected by atomic state.

Successful reasons are ``Matched``, ``Drifted``, and ``Resynchronized``.

Do not rely on credential verification to validate method configuration.
Configuration is checked first and can throw even if the submitted OTP is
malformed.

Protocol bounds
---------------

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Input
     - Bound
   * - HOTP/TOTP decoded Base32 secret
     - 16–1024 bytes
   * - Generated secret
     - 16–1024 caller-selected bytes; 20 by default
   * - HOTP/TOTP digits
     - 6–9
   * - Algorithms
     - SHA-1, SHA-256, SHA-512
   * - HOTP counter
     - 0 through ``PHP_INT_MAX``
   * - HOTP look-ahead
     - 0–100 without integer overflow
   * - TOTP period
     - 1–86400 seconds
   * - TOTP verification drift
     - Past + future at most 100 steps
   * - Timestamp
     - 0 through ``PHP_INT_MAX``

Generic OTP bounds
------------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - HMAC key
     - 16–1024 bytes
   * - Digits
     - 6–10
   * - TTL
     - 1–86400 seconds
   * - Maximum attempts
     - 1–10
   * - Binding
     - 1–4096 bytes

Recovery-code bounds
--------------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - HMAC key
     - 16–1024 bytes
   * - Binding
     - 1–190 bytes
   * - Batch count
     - 1–100
   * - Unformatted code length
     - 6–128
   * - Group size
     - 0 through code length
   * - Normalized entropy
     - At least 40 bits per code
   * - Raw submitted input
     - At most 512 bytes

OCRA bounds
-----------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - Raw/decoded key
     - 16–1024 bytes
   * - Decimal output
     - 4–9 digits
   * - Full HMAC output
     - 40/64/128 hexadecimal characters
   * - Challenge declaration
     - 4–64 maximum characters/nibbles
   * - Composite mutual challenge
     - At most 128 bytes
   * - PIN
     - Non-empty, at most 1024 bytes
   * - Session declaration
     - 1–512 bytes
   * - Factor ID
     - 1–190 bytes
   * - Replay TTL
     - Positive and sufficient for time window

Provisioning bounds
-------------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - Complete URI
     - 1–4096 bytes
   * - Combined issuer/label
     - At most 255 UTF-8 bytes
   * - Additional parameters when building
     - At most 24
   * - Parsed query parameters
     - At most 32
   * - Extension key
     - 1–64 printable bytes
   * - Extension string value
     - At most 1024 bytes
   * - QR image size
     - 64–4096 pixels

Verification-window examples
----------------------------

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $exact = new VerificationWindow();
   $onePast = new VerificationWindow(past: 1);
   $oneEachSide = new VerificationWindow(1, 1);
   $symmetric = VerificationWindow::symmetric(2); // total is 4

``symmetric(51)`` is invalid because total drift would be 102.

Safe error boundary
-------------------

.. code-block:: php

   try {
       $result = $totp->verifyWithWindow(
           $submitted,
           cache: $stateCache,
           factorId: $factorId,
       );
   } catch (InvalidArgumentException $exception) {
       // Deployment/programming error: alert internally, reveal no secret values.
       return $temporaryFailure;
   } catch (Throwable $exception) {
       // Store/runtime failure: fail closed and log only redacted metadata.
       return $temporaryFailure;
   }

   if (!$result->matched) {
       return $genericCredentialFailure;
   }

Detailed reasons are useful for internal tests and observability. Avoid exposing
them when they reveal factor existence, configuration, timing, or replay state.
