Migration Notes
===============

Recent versions expanded the package beyond the earlier minimal OTP surface. The most important changes are below.

Generic OTP
-----------

- Generic OTP codes are now strings, not integers.
- Leading zeroes are preserved.
- The generic OTP class now expects a caller-provided PSR-6 cache pool.
- Digit count is validated as OTP digits, not PHP integer size.
- Generic OTP now accepts only ``sha256`` and ``sha512`` for stored-code digests.
- Signature cache keys now use SHA-256. Outstanding cache entries created with the earlier ``xxh3`` key format are intentionally not reused.
- Validity is bounded to 86400 seconds, retries to 100, and signatures to 4096 bytes.
- An optional final ``hashKey`` constructor argument enables keyed HMAC storage without changing existing positional arguments.

TOTP
----

- The old boolean leeway model has been replaced by configurable past/future windows.
- A simple boolean API remains available through ``verify()``.
- Richer inspection is available through ``verifyWithWindow()`` and ``VerificationResult``.
- Verification windows are bounded to 100 total drift steps and TOTP periods to 86400 seconds.
- Malformed submitted codes return a non-matching result instead of using exceptions for expected verification flow.

HOTP
----

- ``verify()`` supports a look-ahead window.
- ``verifyWithResult()`` returns matched counter and drift information.
- HOTP look-ahead is bounded to 100 counters.

Provisioning
------------

- ``otpauth://`` parsing is now available.
- Enrollment payload helpers expose URI, QR payload, and optional SVG.
- Label and issuer handling is stricter and centralized.
- Parsing rejects duplicate parameters, conflicting label/query issuers, invalid Base32 encodings, and oversized URIs.

Recovery codes and replay protection
------------------------------------

- Recovery code generation and consumption are now first-class features.
- Replay protection is pluggable through interfaces and in-memory stores.
- ``AtomicReplayStoreInterface`` adds atomic consume-once and monotonic advance operations for concurrency-safe replay protection.
- OCRA generated Base32 secrets should be constructed with ``OCRA::fromBase32()``; the constructor continues to accept raw key bytes for RFC test-vector and binary-key compatibility.
