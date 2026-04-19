Storage Guidance
================

Secrets
-------

OTP secrets are reversible secrets. If your application must generate future codes, hashing alone is not enough.

Recommended practice:

- store OTP secrets encrypted at rest
- keep encryption keys outside the primary application database when possible
- version secret records so rotation and grace-period overlap can be tracked safely
- prefer a separate secret reference in enrollment records instead of duplicating raw secrets everywhere

The package includes ``Infocyph\OTP\Contracts\SecretStoreInterface`` for applications that want an explicit abstraction around secret persistence.

Recovery codes
--------------

Recovery codes should usually be stored hashed.

Recommended practice:

- hash each recovery code before storage
- store one row per code or per active batch plus child rows
- track ``used_at`` or equivalent consumption state atomically
- revoke or replace the old active batch when issuing a new set
- expose derived metadata such as total issued, remaining, and last used

Replay state
------------

Replay state can live in cache or a database depending on your durability needs.

Recommended practice:

- use durable storage for HOTP counters and any state that must survive restarts
- use token-expiry or cleanup jobs for consumed TOTP/OCRA replay tokens
- index by namespace, binding, and token
- keep replay data logically separate from secrets and recovery-code hashes

Generic OTP
-----------

Generic OTP requires a caller-provided PSR-6 cache pool implementation.

Contracts
---------

The package includes contracts you can implement in your own infrastructure:

- ``Infocyph\OTP\Contracts\ReplayStoreInterface``
- ``Infocyph\OTP\Contracts\RecoveryCodeStoreInterface``
- ``Infocyph\OTP\Contracts\SecretStoreInterface``

Implementation examples
-----------------------

See :doc:`custom-stores` for a step-by-step guide to building persistent database-backed implementations for:

- recovery code tracking
- replay tracking
- secret storage design guidance
- day-to-day metadata such as total issued, remaining, and last-used time
