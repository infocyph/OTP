Errors, results, and limits
===========================

The API distinguishes programmer/configuration errors, malformed transport data,
normal credential failure, replay, and infrastructure failure.

Exceptions
----------

Invalid configuration or protocol input throws ``InvalidArgumentException``.
Examples include weak secrets, unsupported algorithms, negative timestamps,
invalid OCRA suites, malformed AOTP/GridOTP transport objects, invalid Passkey RP
configuration, invalid MobileOTP Init-Secrets/PINs, invalid provisioning URIs,
and cache/factor-ID mismatches or unsafe authentication-state caches.

Optional integrations fail explicitly:

* constructing/using AOTP without ``ext-sodium`` throws ``LogicException``;
* constructing Passkey without ``web-auth/webauthn-lib`` throws
  ``LogicException``.

Use ``AOTP::isAvailable()`` and ``Passkey::isAvailable()`` when feature exposure
depends on runtime capability.

Corrupt authentication state, invalid durable WebAuthn ``CredentialRecord``
data, serialization failures, and CacheLayer/store mutation failures are
operational errors and may throw ``RuntimeException`` or an underlying backend
exception. Catch them at the application boundary and fail closed.

Normal verification failure
---------------------------

Boolean verification methods return ``false``. Detailed HOTP, TOTP, OCRA, AOTP,
GridOTP, and MobileOTP methods return ``VerificationResult`` with one of:

* ``Malformed`` — wrong submitted credential shape/character class;
* ``Mismatch`` — valid shape but no acceptable cryptographic/protocol candidate;
* ``Replay`` — a valid candidate was already consumed or monotonic state is
  already equal/higher.

Successful reasons are ``Matched``, ``Drifted``, and ``Resynchronized`` where the
protocol supports drift/resynchronization.

Passkey uses ``PasskeyResult`` with the same failure reasons. A successful
Passkey result is ``Matched`` and carries the durable ``credentialRecordJson``
that the application must persist.

Do not rely on credential verification to validate method configuration.
Configuration is checked first and can throw even if submitted input is
malformed.

HOTP/TOTP bounds
----------------

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

AOTP bounds
-----------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - Factor ID
     - 1–190 bytes
   * - Audience
     - Valid UTF-8, 1–255 bytes, without whitespace/control characters
   * - Context
     - Valid UTF-8, 1–4096 bytes, without control characters
   * - Challenge TTL
     - 1–600 seconds
   * - Challenge ID
     - Exactly 16 random bytes before URL-safe Base64
   * - Nonce
     - Exactly 32 random bytes before URL-safe Base64
   * - Ed25519 public key
     - Exactly 32 bytes before URL-safe Base64
   * - Ed25519 private key
     - Exactly 64 bytes before URL-safe Base64
   * - Detached signature
     - Exactly 64 bytes before URL-safe Base64

``AotpChallenge::fromArray()`` and ``AotpResponse::fromArray()`` require exact,
versioned transport shapes. Unknown/missing fields or invalid encoded lengths are
rejected with ``InvalidArgumentException``.

``AOTP::respond()`` additionally requires independently supplied
``expectedAudience`` and ``expectedContext`` values. A mismatch in either throws
``InvalidArgumentException`` before signing. The client also rejects a challenge
before its ``issuedAt`` timestamp or at/after ``expiresAt``. The optional
``now`` parameter exists for deterministic tests/integration clocks.

GridOTP bounds
--------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - Secret alphabet
     - ``ABCDEFGHJKLMNPQRSTUVWXYZ23456789``
   * - Secret length
     - 8–32 symbols; generated default 12
   * - Challenge size
     - 6–10 distinct one-based positions, not above secret length
   * - Challenge TTL
     - 1–900 seconds
   * - Maximum attempts
     - 1–10
   * - Factor ID
     - 1–190 bytes
   * - Response
     - Decimal digits, exactly one digit per requested position
   * - Challenge ID
     - Exactly 16 random bytes before URL-safe Base64

The transported grid must contain every secret-alphabet symbol exactly once and
its decimal labels must remain balanced at three or four occurrences per digit.
Tampered transport objects are rejected or fail challenge-integrity verification.

MobileOTP bounds
----------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - Init-Secret
     - Exactly 16 hexadecimal characters; case is significant to calculation
   * - PIN
     - Exactly 4 decimal digits
   * - Output
     - Exactly 6 lowercase hexadecimal characters
   * - Period
     - Fixed at 10 seconds
   * - Verification window
     - At most 18 ten-second steps in each direction
   * - Fixed offset
     - At most 8640 steps (24 hours) in either direction
   * - Factor ID
     - 1–190 bytes when replay protection is enabled

MobileOTP's ``VerificationWindow`` is tighter than the generic window object's
100-total-step limit.

Passkey/WebAuthn bounds
-----------------------

.. list-table::
   :header-rows: 1

   * - Input
     - Bound
   * - RP ID
     - Host name, at most 253 bytes; no scheme/path/whitespace
   * - Allowed origins
     - 1–16 unique exact origins
   * - Ceremony TTL
     - 1–600 seconds
   * - Binding
     - 1–190 bytes
   * - User handle
     - 1–64 bytes
   * - Username/display name
     - Valid UTF-8, 1–255 bytes
   * - Existing/allowed credential records
     - At most 64 serialized records
   * - Browser credential/record JSON
     - 1–131072 bytes per supplied JSON string
   * - Ceremony ID
     - Exactly 16 random bytes before URL-safe Base64

Plain HTTP origins are accepted only for localhost/loopback development.
Malformed browser credential JSON returns ``PasskeyResult::malformed()`` where it
is normal untrusted input; corrupt stored WebAuthn options/credential records are
operational failures and fail closed.

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

``otpauth://`` provisioning applies to HOTP/TOTP and the package's explicit OCRA
client convention. AOTP, GridOTP, MobileOTP, and Passkey do not use it.

Verification-window examples
----------------------------

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $exact = new VerificationWindow();
   $onePast = new VerificationWindow(past: 1);
   $oneEachSide = new VerificationWindow(1, 1);
   $symmetric = VerificationWindow::symmetric(2); // total drift is 4

``symmetric(51)`` is invalid because total drift would be 102. A protocol can
impose a smaller limit, as MobileOTP does.

Safe error boundary
-------------------

.. code-block:: php

   try {
       $result = $totp->verifyWithWindow(
           $submitted,
           cache: $stateCache,
           factorId: $factorId,
       );
   } catch (InvalidArgumentException|LogicException $exception) {
       // Deployment/programming/capability error: alert internally, reveal no secrets.
       return $temporaryFailure;
   } catch (Throwable $exception) {
       // Store/runtime failure: fail closed and log only redacted metadata.
       return $temporaryFailure;
   }

   if (!$result->matched) {
       return $genericCredentialFailure;
   }

Detailed reasons are useful for internal tests and observability. Avoid exposing
them when they reveal factor existence, configuration, timing, replay state, or
WebAuthn credential routing.
