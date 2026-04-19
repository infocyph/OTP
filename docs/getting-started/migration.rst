Migration Notes
===============

Recent versions expanded the package beyond the earlier minimal OTP surface. The most important changes are below.

Generic OTP
-----------

- Generic OTP codes are now strings, not integers.
- Leading zeroes are preserved.
- The generic OTP class now expects a caller-provided PSR-6 cache pool.
- Digit count is validated as OTP digits, not PHP integer size.

TOTP
----

- The old boolean leeway model has been replaced by configurable past/future windows.
- A simple boolean API remains available through ``verify()``.
- Richer inspection is available through ``verifyWithWindow()`` and ``VerificationResult``.

HOTP
----

- ``verify()`` supports a look-ahead window.
- ``verifyWithResult()`` returns matched counter and drift information.

Provisioning
------------

- ``otpauth://`` parsing is now available.
- Enrollment payload helpers expose URI, QR payload, and optional SVG.
- Label and issuer handling is stricter and centralized.

Recovery codes and replay protection
------------------------------------

- Recovery code generation and consumption are now first-class features.
- Replay protection is pluggable through interfaces and in-memory stores.
