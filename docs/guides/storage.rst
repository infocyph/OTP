CacheLayer state and durable persistence
========================================

Generic OTP and replay protection use ``infocyph/cachelayer`` directly.
Recovery codes deliberately keep ``RecoveryCodeStoreInterface`` because their
batch history is durable application data, not expiring authentication cache.
For adapter-specific connection, TLS, cluster, and deployment options, consult
the `CacheLayer 3.1 documentation <https://github.com/infocyph/CacheLayer/tree/3.1>`_.
The examples below show the OTP-specific safety settings. CacheLayer's factory
configures the matching lock provider, and OTP consumes that capability from the
cache itself.

Required CacheLayer policy
--------------------------

Authentication state must fail closed. Always construct the cache with:

.. code-block:: php

   use Infocyph\CacheLayer\Cache\CacheOptions;

   $options = new CacheOptions(
       integrityKey: $cacheIntegrityKey,
       allowClosures: false,
       allowObjects: false,
       failOpen: false,
   );

``failOpen: false`` is mandatory. CacheLayer's general-purpose default treats a
read failure like a miss; that is useful for ordinary cached content but unsafe
for OTP state because missing replay state can permit a credential again.

The integrity key authenticates CacheLayer payloads but does not encrypt them.
Protect the backend, its transport, credentials, and backups. Keep the integrity
key in a secret manager and plan rotation because changing it invalidates
existing entries.

Use a dedicated namespace such as ``infocyph-otp``. Do not share it with
application response caches, and never call ``clear()`` or a namespace-wide
flush from an OTP flow.

Cache and lock pairing
----------------------

Every stateful operation receives one CacheLayer
``AuthenticationStateCacheInterface``. OTP obtains its lock from that same
object, removing the independently pairable cache/lock arguments. The cache is
rejected unless it is fail-closed, payload-integrity protected, authoritative,
and exposes a configured state lock. Lock acquisition is bounded and any
acquisition, ownership-refresh, read, write, or delete failure aborts the
authentication operation with an exception.

Do not call ``Cache::remember()`` to implement OTP transitions. Its
lock-contention fallback may compute without the lock; OTP performs the entire
read/decision/mutation sequence under CacheLayer's configured lock provider.

Redis example
-------------

.. code-block:: php

   use Infocyph\CacheLayer\Cache\Cache;

   $redis = new Redis();
   $redis->connect('cache.internal', 6379, 1.0);
   $redis->auth($redisPassword);

   $stateCache = Cache::redis(
       namespace: 'infocyph-otp',
       client: $redis,
       options: $options,
   );

Use a primary/authoritative Redis connection. Replicas with lag are unsafe for
verification reads. Configure memory so authentication keys are not evicted.
HOTP and counter-OCRA state has no TTL and must survive restarts and failover.

PDO example
-----------

.. code-block:: php

   use Infocyph\CacheLayer\Cache\Cache;

   $pdo = new PDO($dsn, $username, $password, [
       PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
   ]);

   $stateCache = Cache::pdo(
       namespace: 'infocyph-otp',
       pdo: $pdo,
       table: 'otp_cache_entries',
       options: $options,
   );

``Cache::pdo()`` configures its PDO lock provider from the same connection. Test
the target engine's lock behavior. SQLite is useful for local integration tests; production
multi-host deployments normally require a network database or Redis.

Local development example
-------------------------

.. code-block:: php

   use Infocyph\CacheLayer\Cache\Cache;

   $stateCache = Cache::file(
       namespace: 'infocyph-otp-dev',
       dir: __DIR__ . '/var/cache/otp',
       options: $options,
   );

``Cache::file()`` configures a file lock. File locks coordinate only processes
sharing that filesystem. ``Cache::memory``
and file-backed examples are not suitable for multiple hosts, containers, or
durability across deployment replacement.

State by primitive
------------------

.. list-table:: Backend suitability
   :header-rows: 1
   :widths: 22 25 53

   * - Primitive
     - State lifetime
     - Backend requirement
   * - ``GenericOtp``
     - Short challenge TTL
     - Shared, fail-closed, authoritative, integrity-protected, lockable
   * - TOTP
     - Short replay TTL
     - Shared, authoritative, integrity-protected, lockable
   * - HOTP
     - Factor lifetime
     - Durable, non-evicting, authoritative, integrity-protected, lockable
   * - Counter OCRA
     - Factor lifetime
     - Durable, non-evicting, authoritative, integrity-protected, lockable
   * - Challenge OCRA
     - Application replay TTL
     - Shared, authoritative, integrity-protected, lockable
   * - Recovery codes
     - Durable
     - Application-owned atomic persistence

``Cache::memory`` is for tests only. File cache/lock is limited to local or one
shared-filesystem deployment. A tiered L1/L2 cache is rejected for replay and
counter state because a stale promoted read can reopen an accepted moving
factor. Replica reads and eventually consistent backends are not allowed.
Evicting HOTP or counter-OCRA state is unsafe because those records must survive
for the complete factor generation.

.. list-table::
   :header-rows: 1
   :widths: 22 30 18 30

   * - Primitive
     - Cached value
     - Lifetime
     - Loss consequence
   * - Generic OTP
     - Versioned digest/attempt/expiry array
     - Configured challenge TTL
     - Active challenge becomes unusable
   * - TOTP
     - Greatest accepted timestep integer
     - ``period * accepted-window-size``
     - A still-valid timestep may replay
   * - HOTP
     - Greatest accepted counter integer
     - No TTL
     - Older counters may reopen
   * - Counter OCRA
     - Greatest accepted counter integer
     - No TTL
     - Older counters may reopen
   * - Non-counter OCRA
     - One scalar token per authenticated message
     - Required application TTL
     - The message may replay during validity
   * - Recovery codes
     - Application-defined durable rows
     - Until replacement/consumption
     - Recovery access or audit state is corrupted

All package cache keys are full lowercase SHA-256 hex identifiers derived from a
versioned domain and the binding/factor/message context. Raw bindings, factor
IDs, OTP values, challenges, and secrets are not embedded in cache keys. Values
are native arrays or integers; the package adds no JSON or PHP serialization
layer.

Application persistence is separate
------------------------------------

CacheLayer is not the persistence answer for the complete MFA domain. Keep
encrypted OTP secrets, factor ownership and status, HOTP's application
``nextCounter``, recovery-code batches, device/user relationships, key-version
metadata, and audit logs in the application's authoritative durable stores.
CacheLayer holds only the challenge and replay/counter values listed above.

TTL rules
---------

Generic OTP stores an absolute expiration inside the record as well as a backend
TTL. Failed attempts preserve that absolute expiration and write only the
remaining lifetime. TOTP's derived TTL covers every accepted past/current/future
step. Non-counter OCRA requires ``replayTtl``; time suites reject a value shorter
than the complete acceptance window.

HOTP and counter-OCRA intentionally pass no TTL. Their monotonic record must be
durable for the factor generation. If an operational policy deletes it, rotate
to a new factor ID and reset/migrate the application counter in one controlled
operation—never silently recreate state under the old generation.

Failure handling and observability
----------------------------------

Treat CacheLayer exceptions as temporary authentication infrastructure failure,
not credential mismatch. Return a generic client response, retain the original
exception for internal diagnostics, and log only a redacted operation name and
correlation ID. Never log cache keys, values, factor IDs, bindings, submitted
codes, or provisioning URIs.

Lock release is post-operation cleanup. If both the state operation and release
fail, the original read/write/delete exception is preserved. If a mutation was
verified and committed before release cleanup fails, the committed authentication
outcome is retained; the bounded lock lease limits failed cleanup.

Monitor read/write/delete latency, lock acquisition failures, lock contention,
backend errors, evictions, memory pressure, and durable-store replication or
failover health. Alert on unexpected loss of no-TTL counter records.

Recovery-code persistence
-------------------------

``RecoveryCodeStoreInterface`` remains the application extension point. Its
``replace()`` and ``consume()`` operations must each be atomic and must return
metadata from the committed mutation. A relational implementation normally
uses one batch row and child digest rows with a unique
``(binding, digest)`` key. See :doc:`custom-stores` for the full contract.

Required integration tests
--------------------------

Run against every production backend and topology:

* two identical successful submissions yield exactly one acceptance;
* lower/equal monotonic values lose to a stored higher value;
* Generic OTP wrong attempts decrement exactly once without extending expiry;
* issue racing verify has a serializable replacement-or-consumption outcome;
* lock timeout, lost ownership, read, write, and delete failure all fail closed;
* expired TOTP and non-counter OCRA entries follow documented TTL precision;
* backend restart/failover preserves HOTP and counter-OCRA state; and
* namespace flushing and eviction policy cannot remove authentication state.
