State contracts
===============

OTP state uses CacheLayer's public contracts directly:

.. code-block:: php

   use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
   use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;

``AuthenticationStateCacheInterface`` exposes the effective fail-open,
payload-integrity, authoritative-read, and cache-owned lock capabilities.
CacheLayer 3.3 caches may additionally implement ``AtomicCacheProviderInterface``
and return an ``AtomicCacheInterface`` for native conditional mutation. Generic
OTP, HOTP, TOTP, and OCRA do not expose an OTP-specific cache, lock wrapper, or
replay adapter.

For authentication calls, configure ``failOpen: false``, an ``integrityKey``,
and one authoritative direct backend. TOTP, HOTP, and OCRA accept either the
native CacheLayer atomic capability or the cache's coordinated lock fallback.
``GenericOtp`` requires the coordinated lock because its record is a multi-field
state machine. OTP validates these capabilities before mutation. A cache and
factor ID are required together on optional replay-aware protocol methods. See
:doc:`../guides/storage` for backend examples and failure semantics.

RecoveryCodeStoreInterface
--------------------------

.. code-block:: php

   namespace Infocyph\OTP\Contracts;

   use DateTimeImmutable;

   interface RecoveryCodeStoreInterface
   {
       public function consume(
           string $binding,
           string $hashedCode,
           DateTimeImmutable $usedAt,
       ): array;

       public function metadata(string $binding): array;

       public function replace(
           string $binding,
           array $hashedCodes,
           DateTimeImmutable $issuedAt,
       ): array;
   }

``consume()`` returns:

.. code-block:: php

   [
       'consumed' => true,
       'total' => 10,
       'remaining' => 9,
       'lastUsedAt' => $usedAt,
   ]

The values must describe the state committed by the same mutation.
``metadata()`` returns ``total``, ``remaining``, and ``lastUsedAt``, using
zero/zero/null when no active batch exists. ``replace()`` atomically replaces the
complete batch and returns committed metadata.

All ``hashedCodes`` are unique lowercase HMAC-SHA-256 hex values. An
implementation must reject or safely handle duplicates rather than silently
reducing the batch. Plaintext codes and the HMAC key never cross the contract.

Bundled implementation
----------------------

.. code-block:: php

   use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

``InMemoryRecoveryCodeStore`` is deterministic and process-local. Use it for unit
tests or one-process development only. Production implementations must provide
durable atomic replacement and consumption.

Production requirements
-----------------------

A conforming recovery-code store documents:

* transaction primitive and isolation level;
* lock/conflict and deadlock-retry behavior;
* authoritative writer/replica behavior;
* unknown-commit handling;
* identifier and digest collation;
* retention, backup, deletion, and capacity policy; and
* real multi-process concurrency test coverage, including replacement racing
  consumption.

See :doc:`../guides/custom-stores` for a relational outline and complete test
matrix.
