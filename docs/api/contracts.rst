Store contracts
===============

``OtpStoreInterface``
   Atomic issue/replace, verify-and-consume/decrement, and scoped delete for
   Generic OTP.

``ReplayStoreInterface``
   Atomic consume-once and monotonic advance for TOTP, HOTP, and OCRA.

``RecoveryCodeStoreInterface``
   Atomic batch replacement and consumption that return committed state, plus
   independent metadata lookup.

Application implementations are public substitution boundaries. No contract
permits a non-atomic fallback.
