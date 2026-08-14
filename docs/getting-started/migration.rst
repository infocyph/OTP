Major-version migration
=======================

This release intentionally has no compatibility layer.

* ``OTP`` is now ``GenericOtp`` and requires ``OtpStoreInterface`` plus an HMAC key.
* ``getOTP()`` is now ``generate()``.
* HOTP/TOTP algorithm configuration is constructor-only; HOTP has no stored counter.
* OCRA PIN, session, counter, and timestamp are operation arguments.
* Replay stores expose only atomic ``consumeOnce`` and ``advance``.
* Verification reasons are ``VerificationReason`` enum cases.
* HOTP/counter OCRA results expose ``nextCounter``.
* Convenience provisioning APIs no longer accept include flags.
* Step-up policy, device enrollment, secret storage, PSR-6 fallback, and ``flush`` were removed.
* HOTP/TOTP require 128-bit secrets and 6..9 digits; OCRA truncation is 4..9.
