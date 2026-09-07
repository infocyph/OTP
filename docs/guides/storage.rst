CacheLayer state and durable persistence
========================================

OTP uses ``infocyph/cachelayer`` for package-owned authentication state.
Recovery codes and Passkey credential records deliberately remain durable
application data rather than authentication cache. For adapter-specific
connection, TLS, cluster, and deployment options, consult the `CacheLayer 3.3
documentation <https://github.com/infocyph/CacheLayer/tree/3.3>`_.

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
for authentication state because missing replay state can permit a credential
again.

The integrity key authenticates CacheLayer payloads but does not encrypt them.
Protect the backend, its transport, credentials, and backups. Keep the integrity
key in a secret manager and plan rotation because changing it invalidates
existing entries.

Use a dedicated namespace such as ``infocyph-otp``. Do not share it with
application response caches, and never call ``clear()`` or a namespace-wide
flush from an OTP flow.

Atomic and lock capability pairing
----------------------------------

Every stateful operation receives one CacheLayer
``AuthenticationStateCacheInterface``. OTP rejects the cache unless it is
fail-closed, payload-integrity protected, and backed by one authoritative direct
backend.

TOTP, HOTP, OCRA, MobileOTP, and AOTP use CacheLayer 3.3 native atomics where
their scalar transition maps safely to conditional mutation. If native atomics
are not available, those paths use the lock provider returned by
``authenticationStateLock()``.

``GenericOtp``, ``GridOTP``, and ``Passkey`` deliberately remain lock-based
because their issue/verify/attempt/expiry/consumption records mutate multiple
fields as one serializable state machine. An atomic capability alone is not
sufficient for those primitives; their cache must expose a coordinated lock.

Capability selection is not runtime failover. Once an atomic capability is
selected, an atomic backend exception propagates and OTP does not retry the same
mutation through locks. This prevents re-executing a mutation after an unknown
commit outcome.

Lock acquisition is bounded and any acquisition, ownership-refresh, read,
write, or delete failure aborts the authentication operation with an exception.
Do not call ``Cache::remember()`` to implement authentication transitions.

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
CacheLayer 3.3 Redis/Valkey adapters expose native atomic replay operations, so
eligible scalar transitions use that path without acquiring replay locks.

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

When the selected adapter does not expose CacheLayer's atomic capability, OTP
uses the lock returned by the authentication-state cache. Test the target
engine's lock behavior. SQLite is useful for local integration tests; production
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

File-backed state coordinates only processes sharing that filesystem.
``Cache::memory`` and file-backed examples are not suitable for multiple hosts,
containers, or durability across deployment replacement.

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
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - HOTP
     - Factor lifetime
     - Durable, non-evicting, authoritative, integrity-protected, atomic or lockable
   * - Counter OCRA
     - Factor lifetime
     - Durable, non-evicting, authoritative, integrity-protected, atomic or lockable
   * - Challenge OCRA
     - Application replay TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - AOTP
     - Challenge TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - GridOTP
     - Challenge TTL
     - Shared, authoritative, integrity-protected, lockable
   * - MobileOTP
     - Short monotonic replay TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - Passkey ceremony
     - Ceremony TTL
     - Shared, authoritative, integrity-protected, lockable
   * - Recovery codes
     - Durable
     - Application-owned atomic persistence
   * - Passkey CredentialRecord
     - Credential lifetime
     - Application-owned authoritative durable persistence

``Cache::memory`` is for tests only. File cache/lock is limited to local or one
shared-filesystem deployment. A tiered L1/L2 cache is rejected for authentication
state because a stale promoted read can reopen accepted state. Replica reads and
eventually consistent backends are not allowed. Evicting HOTP or counter-OCRA
state is unsafe because those records must survive for the complete factor
generation.

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
   * - AOTP
     - Reserved/consumed scalar for the exact canonical challenge
     - Challenge TTL
     - Issued challenge may become unusable or replayable if state is lost
   * - GridOTP
     - Versioned digest/attempt/expiry/consumed record
     - Challenge TTL
     - Active challenge state is lost
   * - MobileOTP
     - Greatest accepted timestep integer
     - Replay window lifetime
     - A still-valid timestep may replay
   * - Passkey ceremony
     - Versioned ceremony type/options/binding/expiry/consumed record
     - Ceremony TTL
     - Active ceremony becomes unusable; consumed marker loss can obscure replay
   * - Recovery codes
     - Application-defined durable rows
     - Until replacement/consumption
     - Recovery access or audit state is corrupted
   * - Passkey CredentialRecord
     - Application-defined durable row
     - Credential lifetime
     - Authentication/counter/backup state is lost or stale

All package cache keys are full lowercase SHA-256 hex identifiers derived from a
versioned domain and the binding/factor/message/challenge context. Raw bindings,
factor IDs, OTP values, challenges, and secrets are not embedded in cache keys.
Values are native arrays or integers; the package adds no PHP serialization
layer.

AOTP state is keyed from the factor ID plus the complete canonical challenge,
including its audience, mandatory context, nonce, issuance and expiration. A
modified challenge therefore cannot address the reservation for the original
challenge.

Application persistence is separate
------------------------------------

CacheLayer is not the persistence answer for the complete authentication domain.
Keep these in authoritative durable application storage:

* encrypted HOTP/TOTP/OCRA/GridOTP/MobileOTP secrets and factor ownership/status;
* HOTP's application ``nextCounter``;
* AOTP public-key/factor generation/audience metadata while keeping the private
  key on the client/device;
* Passkey serialized ``CredentialRecord`` data, user association, status and
  revocation metadata;
* recovery-code batches;
* key-version metadata; and
* audit logs.

Passkey ``CredentialRecord`` must be updated after every successful assertion
because counter/backup/user-verification state may change. CacheLayer stores only
the short-lived Passkey ceremony, never the durable credential record.

TTL rules
---------

Generic OTP and GridOTP store absolute expiration inside their records as well
as backend TTL. Failed attempts preserve the absolute expiration and write only
the remaining lifetime. TOTP/MobileOTP replay TTL covers the accepted moving
window. Non-counter OCRA requires ``replayTtl``; time suites reject a value
shorter than the complete acceptance window.

AOTP reserves the challenge until its expiry. After a valid signature, the same
reservation is marked consumed for the remaining lifetime so another valid
submission can be identified as replay. AOTP signing/verification additionally
enforce challenge timestamps; client signing must not bypass those checks to
compensate for bad clock synchronization.

Passkey ceremony records retain a consumed marker only until the original
ceremony expiry. The durable WebAuthn credential remains application-owned after
that state disappears.

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
codes, provisioning URIs, AOTP challenge context/signatures, or Passkey ceremony
payloads.

Atomic ``setIfAbsent()``/``compareAndSet()`` failures and bounded-contention
exhaustion are operational failures and propagate. OTP never converts them to a
mismatch/replay result and never falls back to locks after an atomic operation
has been selected.

Lock release is post-operation cleanup. If both the state operation and release
fail, the original read/write/delete exception is preserved. If a mutation was
verified and committed before release cleanup fails, the committed authentication
outcome is retained; the bounded lock lease limits failed cleanup.

Monitor read/write/delete latency, atomic CAS/set-if-absent latency and
contention, lock acquisition failures, lock contention, backend errors,
evictions, memory pressure, and durable-store replication or failover health.
Alert on unexpected loss of no-TTL counter records.

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
* native atomic adapters select the atomic path without acquiring replay locks;
* adapters without atomics produce equivalent results through lock fallback;
* an available atomic backend failure propagates and is never retried through locks;
* Generic OTP wrong attempts decrement exactly once without extending expiry;
* AOTP duplicate valid signatures consume one reserved challenge exactly once;
* AOTP invalid signatures do not expose consumed state as replay;
* GridOTP attempts/expiry/consumption remain serializable under concurrency;
* Passkey duplicate ceremony completion succeeds at most once;
* issue racing verify has a serializable replacement-or-consumption outcome;
* atomic contention is bounded and fails closed;
* lock timeout, lost ownership, read, write, and delete failure all fail closed;
* expired TOTP/MobileOTP and non-counter OCRA entries follow documented TTL precision;
* backend restart/failover preserves HOTP and counter-OCRA state; and
* namespace flushing and eviction policy cannot remove authentication state.
