Authenticator compatibility
===========================

Reviewed 14 August 2026. Third-party behavior changes by app and release, so
verify against the exact clients supported by your deployment before launch.
The broadest starting point is TOTP with SHA-1, six digits, 30 seconds, and a
minimal URI. SHA-256, SHA-512, non-default digits/periods, and OCRA require
explicit client validation. ``otpauth://ocra`` is not standardized by RFC 6287.
