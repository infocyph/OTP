Security model
==============

OTP arithmetic and safe authentication workflow are separate concerns.

Secrets and keys
----------------

Encrypt factor secrets at rest and restrict access. Generic OTP and recovery
codes require separate purpose-specific HMAC-SHA-256 keys of 16..1024 bytes.
Never log factor secrets, HMAC keys, submitted codes, provisioning URIs, or QR
SVGs. PHP sensitive-parameter attributes reduce accidental trace disclosure but
do not replace safe logging.

State and identity
------------------

Authentication state transitions must be atomic. A factor ID identifies one
factor, suite, secret generation, and counter generation; rotate it when state
can reset. Process-local stores are examples only. Apply TLS, endpoint and
account throttling, anti-enumeration policy, delivery controls, audit, and
recovery policy in the application.

Provisioning and rotation
-------------------------

Treat URI and QR payloads as authentication secrets. Plan rotation explicitly,
verify activation in the application, revoke old enrollment state after the
grace period, and never infer durable persistence from ``planRotation()``.
