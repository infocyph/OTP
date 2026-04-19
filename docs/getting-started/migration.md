# Migration Notes

## Generic OTP

- Generic OTP codes are now strings, not integers.
- Leading zeroes are preserved.
- The generic OTP class now expects a caller-provided PSR-6 cache pool.
- Digit count is validated as OTP digits, not PHP integer size.

## TOTP

- The old boolean leeway model has been replaced with configurable past and future windows.
- `verify()` still gives you a boolean API.
- `verifyWithWindow()` returns a `VerificationResult` for richer handling.

## HOTP

- `verify()` now supports look-ahead.
- `verifyWithResult()` returns matched counter and drift metadata.

## Provisioning

- `otpauth://` parsing is now supported.
- Enrollment payload helpers expose URI, QR payload, and optional SVG.
- Label and issuer handling is centralized and stricter.

## Recovery codes and replay protection

- Recovery codes are first-class package features now.
- Replay protection is pluggable through contracts and in-memory stores.
