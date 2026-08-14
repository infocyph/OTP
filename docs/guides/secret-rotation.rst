Secret rotation
===============

``planRotation()`` returns a typed ``SecretRotation`` and optional next
enrollment payload; it does not persist or activate anything. Replacement
secrets are fully canonicalized and must contain at least 128 decoded bits.
Null or zero grace means immediate cutover. Positive grace produces an exclusive
``overlapUntil`` boundary. Applications own activation proof, persistence,
audit, old-secret revocation, and factor-ID versioning.
