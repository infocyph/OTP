Custom durable stores
=====================

The package does not define custom store contracts for Generic OTP or protocol
replay state. Select a CacheLayer 3.3 authentication-state adapter for those
paths; HOTP/TOTP/OCRA use its native atomics when available or its coordinated
lock fallback, while ``GenericOtp`` requires the coordinated lock. See
:doc:`storage`. The only application persistence contract is
``RecoveryCodeStoreInterface`` because recovery-code batches require durable,
auditable lifecycle state.

Recovery-code contract
----------------------

.. code-block:: php

   use DateTimeImmutable;
   use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;

   final class DatabaseRecoveryCodeStore implements RecoveryCodeStoreInterface
   {
       public function consume(
           string $binding,
           string $hashedCode,
           DateTimeImmutable $usedAt,
       ): array {
           // In one transaction:
           // 1. delete exactly one matching digest when present;
           // 2. update last_used_at only after successful deletion;
           // 3. return committed consumed/total/remaining/lastUsedAt.
       }

       public function metadata(string $binding): array
       {
           // Return total/remaining/lastUsedAt.
           // Missing binding means 0, 0, null.
       }

       public function replace(
           string $binding,
           array $hashedCodes,
           DateTimeImmutable $issuedAt,
       ): array {
           // Atomically delete the prior batch, insert this complete unique
           // digest set, reset last_used_at, and return committed metadata.
       }
   }

Return shapes
-------------

``consume()`` returns exactly:

.. code-block:: php

   [
       'consumed' => true,
       'total' => 10,
       'remaining' => 9,
       'lastUsedAt' => $usedAt,
   ]

``replace()`` and ``metadata()`` omit ``consumed``. ``lastUsedAt`` is a
``DateTimeImmutable`` or null. The values returned by ``consume()`` and
``replace()`` must come from the same committed mutation—not a second fallible
query after commit.

Relational model
----------------

One common schema separates batch metadata from one row per digest:

.. code-block:: sql

   CREATE TABLE recovery_batches (
       binding VARCHAR(190) PRIMARY KEY,
       total INTEGER NOT NULL,
       issued_at TIMESTAMP NOT NULL,
       last_used_at TIMESTAMP NULL
   );

   CREATE TABLE recovery_code_digests (
       binding VARCHAR(190) NOT NULL,
       digest CHAR(64) NOT NULL,
       PRIMARY KEY (binding, digest),
       FOREIGN KEY (binding) REFERENCES recovery_batches(binding)
           ON DELETE CASCADE
   );

Use binary/case-sensitive storage for the lowercase HMAC-SHA-256 digest. Keep
the caller's binding within its documented 1–190 byte bound. The plaintext code
and HMAC key must never enter the store.

Atomic consume
--------------

The transaction must serialize two requests for the same digest. Depending on
the database, use a conditional ``DELETE ... RETURNING``, a locked row, or an
equivalent statement. Exactly one request may report ``consumed: true``. Update
``last_used_at`` and compute remaining count in the same transaction.

Do not turn a deadlock, connection loss, timeout, or unknown commit outcome into
``consumed: false``. Propagate infrastructure failures so the endpoint can fail
closed. Blindly retrying an unknown commit may misreport a consumed code; use
idempotency and driver-specific transaction guidance.

Atomic replacement
------------------

Replacement invalidates the old batch completely. Validate that input digests
are unique, then replace metadata and digest rows in one transaction. A reader
must observe either the complete old batch or complete new batch, never an empty
or partial intermediate set. Replacement racing consumption must have one
serializable outcome: the old code is either consumed before replacement or is
invalid after the complete replacement commits.

The in-package ``InMemoryRecoveryCodeStore`` is readable reference behavior for
unit tests and one-process development. It is not durable and does not
coordinate PHP-FPM workers, queue workers, containers, hosts, or restarts.

Operational contract
--------------------

Document and test:

* isolation level and exact row/key lock scope;
* primary-versus-replica consistency;
* deadlock retry and unknown-commit policy;
* binding/digest collation and index limits;
* encrypted backup and retention policy;
* account-deletion behavior;
* audit events without code, digest, or key material; and
* latency/error metrics without sensitive identifiers.

Required tests
--------------

#. replacement returns the complete new count;
#. replacement invalidates every code from the old batch;
#. one code succeeds once and returns the post-delete remaining count;
#. two OS processes racing one code yield one success;
#. concurrent replacement/consumption has a documented serial order;
#. missing metadata is ``total=0``, ``remaining=0``, ``lastUsedAt=null``;
#. rollback preserves the prior batch after injected failure; and
#. database restart/failover never manufactures a success.

Run these tests against every supported database version and production
deployment mode, not only an in-memory substitute.
