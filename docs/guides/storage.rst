CacheLayer state and durable persistence
========================================

OTP uses ``infocyph/cachelayer`` directly for package-owned authentication
state. Recovery codes deliberately keep ``RecoveryCodeStoreInterface`` because
their batch history is durable application data, while Passkey credential
records are also durable application-owned data. For adapter-specific connection,
TLS, cluster, and deployment options, consult the `CacheLayer 3.3 documentation
<https://github.com/infocyph/CacheLayer/tree/3.3>`_.

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
for authentication state because losing replay/challenge state can reopen an
accepted credential or make security decisions ambiguous.

The integrity key authenticates CacheLayer payloads but does not encrypt them.
Protect the backend, its transport, credentials, and backups. Keep the integrity
key in a secret manager and plan rotation because changing it invalidates
existing entries.

Use a dedicated namespace such as ``infocyph-otp``. Do not share it with
application response caches, and never call ``clear()`` or a namespace-wide
flush from an OTP flow.

Atomic and lock capability pairing
----------------------------------

Every stateful primitive receives one CacheLayer
``AuthenticationStateCacheInterface``. OTP rejects the cache unless it is
fail-closed, payload-integrity protected, and backed by one authoritative direct
backend.

The state models fall into two groups.

**Atomic-or-lock scalar transitions**

TOTP, HOTP, counter/non-counter OCRA, MobileOTP, and AOTP use CacheLayer 3.3
native atomics where the transition maps cleanly to monotonic advancement or a
single reservation/claim. Backends without atomics use the coordinated
``authenticationStateLock()`` fallback.

* TOTP, HOTP, counter OCRA, and MobileOTP advance a greatest-accepted integer.
* Non-counter OCRA performs a one-time claim for the authenticated message.
* AOTP reserves a freshly issued challenge and later transitions its scalar
  state from unconsumed to consumed.

**Always-lock multi-field transitions**

``GenericOtp``, ``GridOTP``, and ``Passkey`` always require the coordinated lock
even when the backend also exposes atomics:

* Generic OTP mutates digest, attempts, absolute expiry, and consumption/deletion.
* GridOTP mutates challenge digest, attempts, expiry, and consumed status.
* Passkey mutates ceremony type/options/user binding/expiry/consumed state.

These fields form one serializable state machine and must not be split into
independent cache operations.

Capability selection is not runtime failover. Once an atomic capability is
selected, an atomic backend exception propagates and OTP does not retry the
operation through locks, because the commit outcome might be unknown. Lock
acquisition, ownership refresh, read, write, or delete failure also aborts the
authentication operation.

Do not use ``Cache::remember()`` for authentication mutations; its general cache
semantics do not express compare/claim/consume transitions.

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
scalar OTP transitions can use the native path while GenericOtp, GridOTP, and
Passkey use the configured coordinated lock.

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
   :widths: 20 24 56

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
   * - Non-counter OCRA
     - Application replay TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - AOTP
     - Issued challenge TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - GridOTP
     - Issued challenge TTL
     - Shared, authoritative, integrity-protected, lockable
   * - MobileOTP
     - Short replay TTL
     - Shared, authoritative, integrity-protected, atomic or lockable
   * - Passkey ceremony
     - Short ceremony TTL
     - Shared, authoritative, integrity-protected, lockable
   * - Passkey CredentialRecord
     - Credential lifetime
     - Application-owned authoritative durable database
   * - Recovery codes
     - Until replacement/consumption
     - Application-owned atomic durable persistence

``Cache::memory`` is for tests only. A tiered L1/L2 cache is rejected for
security state because stale promoted reads can reopen accepted state. Replica
reads and eventually consistent backends are not allowed. Evicting HOTP or
counter-OCRA state is unsafe because those records must survive for the complete
factor generation.

.. list-table:: Package state representation
   :header-rows: 1
   :widths: 19 35 20 26

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
     - One scalar claim per authenticated message
     - Required application TTL
     - The message may replay during validity
   * - AOTP
     - Scalar reservation: unconsumed/consumed
     - Challenge TTL
     - Issued proof fails or may lose replay history
   * - GridOTP
     - Version/digest/attempt/expiry/consumed array
     - Challenge TTL
     - Active challenge becomes unusable
   * - MobileOTP
     - Greatest accepted timestep integer
     - Accepted-window TTL
     - A still-valid timestep may replay
   * - Passkey ceremony
     - Version/type/options/user/expiry/consumed array
     - Ceremony TTL
     - Active ceremony becomes unusable
   * - Recovery codes
     - Application-defined durable rows
     - Until replacement/consumption
     - Recovery access or audit state is corrupted

All package cache keys are lowercase SHA-256 identifiers derived from versioned
domains plus binding/factor/challenge context. Raw secrets and submitted OTPs are
not embedded directly in keys. Cache values are native arrays or integers; OTP
adds no extra JSON/PHP serialization layer to CacheLayer state. Passkey's stored
``optionsJson`` is the upstream WebAuthn options payload intentionally retained
inside the integrity-protected ceremony record.

Application persistence is separate
------------------------------------

CacheLayer is not the persistence answer for the complete authentication domain.
Keep the following in authoritative durable application storage:

* encrypted HOTP/TOTP/OCRA/GridOTP/MobileOTP secrets and factor status;
* AOTP public keys and factor/key generation metadata;
* HOTP application ``nextCounter``;
* Passkey user-to-credential relationships and serialized ``CredentialRecord``;
* recovery-code batches through an atomic ``RecoveryCodeStoreInterface``;
* device/user relationships, enrollment status, revocation state, and audit.

The AOTP private key belongs on the client/device, not in verifier persistence.
A Passkey private key remains in the authenticator and is never stored by OTP.

TTL rules
---------

Generic OTP, GridOTP, Passkey ceremonies, and AOTP reservations retain absolute
or protocol-defined expiration behavior and never extend validity on a failed
attempt/mutation. TOTP and MobileOTP derive replay TTL from the complete accepted
window. Non-counter OCRA requires ``replayTtl``; time suites reject a value
shorter than the complete acceptance window.

HOTP and counter-OCRA intentionally use no TTL. Their monotonic record must be
durable for the factor generation. If an operational policy deletes it, rotate
to a new factor ID and reset/migrate the application counter in one controlled
operation—never silently recreate state under the old generation.

Passkey credential records have no CacheLayer TTL because they do not belong in
CacheLayer at all. Persist the updated record returned by every successful
assertion.

Failure handling and observability
----------------------------------

Treat CacheLayer exceptions as temporary authentication infrastructure failure,
not credential mismatch. Return a generic client response, retain the original
exception for internal diagnostics, and log only a redacted operation name and
correlation ID. Never log cache keys, values, factor IDs, bindings, submitted
codes, AOTP challenges/signatures, GridOTP grids/responses, Passkey ceremony
options/browser credentials, or provisioning URIs.

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
evictions, memory pressure, and durable-store replication/failover health.
Alert on unexpected loss of no-TTL counter records.

Recovery-code persistence
-------------------------

``RecoveryCodeStoreInterface`` remains the application extension point. Its
``replace()`` and ``consume()`` operations must each be atomic and must return
metadata from the committed mutation. A relational implementation normally
uses one batch row and child digest rows with a unique ``(binding, digest)`` key.
See :doc:`custom-stores` for the full contract.

Required integration tests
--------------------------

Run against every production backend and topology:

* two identical successful TOTP/HOTP/OCRA/MobileOTP/AOTP submissions yield
  exactly one acceptance where single-use state applies;
* AOTP duplicate valid signatures report replay and tampered challenges cannot
  reach an issued reservation;
* GridOTP wrong attempts decrement exactly once and success is single-use under
  concurrency;
* Passkey ceremony success is single-use and its consumed marker survives until
  original expiry;
* lower/equal monotonic values lose to a stored higher value;
* native atomic adapters select the atomic path without acquiring replay locks;
* adapters without atomics produce equivalent scalar results through lock fallback;
* an available atomic backend failure propagates and is never retried through locks;
* Generic OTP wrong attempts decrement exactly once without extending expiry;
* issue racing verify has a serializable replacement-or-consumption outcome;
* atomic contention is bounded and fails closed;
* lock timeout, lost ownership, read, write, and delete failure all fail closed;
* backend restart/failover preserves HOTP and counter-OCRA state; and
* namespace flushing and eviction policy cannot remove authentication state.
