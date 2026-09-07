Replay protection
=================

A mathematically valid OTP can still be unsafe if accepted twice. Calculation
methods remain stateless for interoperability and enrollment checks, while the
detailed verification methods can use CacheLayer for atomic acceptance state.

Common configuration
--------------------

Pass both values or neither:

* an integrity-protected, fail-closed, authoritative CacheLayer
  ``AuthenticationStateCacheInterface``; and
* a 1–190 byte, generation-specific ``factorId``.

Supplying only part of the pair throws ``InvalidArgumentException``. Unsafe
cache policies and backend failures throw and must produce a temporary
authentication failure.

OTP 6.1 requires CacheLayer 3.3 or newer. Replay transitions use the native
``AtomicCacheProviderInterface`` capability when the configured backend exposes
it. Backends without atomics remain supported when they provide a coordinated
authentication-state lock. Native atomic failures never fall back to locks.

``GenericOtp`` is intentionally different: its multi-field attempt/expiry state
still requires the coordinated lock capability even when the backend also
supports atomics.

See :doc:`storage` for complete Redis, PDO, and local-development setup.

TOTP
----

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $totp->verifyWithWindow(
       otp: $submittedCode,
       timestamp: null,
       window: new VerificationWindow(1, 1),
       cache: $stateCache,
       factorId: 'user-42:totp:secret-v3',
   );

After a cryptographic match, the package stores the greatest accepted timestep.
The TTL is ``period * (past + future + 1)``. Once a future step is accepted,
equal or older steps are replay even if not individually submitted.

With an atomic-capable backend the transition is a bounded
read/``setIfAbsent``/``compareAndSet`` loop. The state can only move forward.
A backend without atomics uses the previous factor-specific coordinated lock
path.

HOTP
----

.. code-block:: php

   $result = $hotp->verifyWithResult(
       otp: $submittedCode,
       counter: $storedNextCounter,
       lookAhead: 10,
       cache: $stateCache,
       factorId: 'user-42:hotp:device-7:counter-v2',
   );

The package stores the greatest accepted counter with no TTL. Equal and lower
counters return ``VerificationReason::Replay``. Persist the application's
``nextCounter`` as durable business state too; the CacheLayer backend used here
must not evict or expire the monotonic replay record.

Atomic-capable backends use the same bounded monotonic CAS algorithm as TOTP.

Counter OCRA
------------

.. code-block:: php

   $result = $ocra->verifyWithResult(
       otp: $submittedResponse,
       challenge: $challenge,
       counter: $counter,
       cache: $stateCache,
       factorId: 'merchant-9:ocra-counter:key-v5',
   );

Counter OCRA uses the same durable greatest-value rule as HOTP. ``replayTtl``
must be null; a TTL is rejected because expiry could reopen older counters.
Atomic-capable backends use the same monotonic CAS path.

Non-counter OCRA
----------------

.. code-block:: php

   $result = $ocra->verifyWithResult(
       otp: $submittedResponse,
       challenge: $challenge,
       pin: $submittedPin,
       session: $sessionContext,
       timestamp: $operationTimestamp,
       timeWindow: new VerificationWindow(1, 1),
       cache: $stateCache,
       factorId: 'merchant-9:ocra-signing:key-v5',
       replayTtl: 300,
   );

The token identity is derived from the complete authenticated OCRA message,
including suite, counter when present, encoded challenge, PIN digest, session,
and matched timestep. The application-supplied TTL is mandatory. It must cover
the complete server challenge/business validity; for time suites it must also be
at least ``timeStepSeconds * (past + future + 1)``.

On atomic-capable backends, first acceptance is one native ``setIfAbsent``
claim. A false conditional result is inspected as existing state: the canonical
value means replay, malformed state throws, and transient contention is retried
within the bounded retry budget.

Factor identity
---------------

A factor ID must distinguish account, protocol, suite/configuration, secret
generation, and any generation in which a moving counter can reset. Examples:

.. code-block:: text

   user-42:totp:secret-v3
   user-42:hotp:device-7:counter-v2
   merchant-9:ocra-signing:key-v5

The raw factor ID is hashed into the package key. Hashing prevents direct
disclosure in backend key listings but does not make reuse safe. Change the ID
when a secret rotates, a suite changes, or a counter legitimately resets.

Stateless verification
----------------------

``TOTP::verify()``, ``HOTP::verify()``, ``OCRA::verify()``, and detailed calls
without cache/factor ID perform only OTP mathematics. This is appropriate
for test vectors, enrollment confirmation, or a caller that performs an
equivalent atomic transition in a larger application transaction. It is not
single-use protection by itself.

Concurrency and failures
------------------------

For every backend, test at least:

#. two concurrent equal matches produce one success and one replay;
#. a higher accepted moving factor prevents a later lower value;
#. different factor generations do not collide;
#. atomic contention is bounded and never regresses state;
#. an atomic backend failure never falls back to an unlocked or lock-based write;
#. lock fallback never writes after lock timeout or ownership loss;
#. malformed persisted replay state throws instead of becoming replay/miss;
#. read/write errors throw instead of becoming a cache miss; and
#. restart, failover, expiry, and eviction match the primitive's durability
   requirements.

Do not use ``Cache::memory`` for production replay state: it coordinates neither
workers nor hosts and disappears on restart. Do not use ``Cache::remember()``
for these transitions because it does not express the required compare/claim
semantics.

Rolling upgrades from 6.0
-------------------------

OTP 6.0 coordinates replay mutations with locks. OTP 6.1 prefers native atomics
when available while keeping the same replay keys and values. Do not run
stateful 6.0 and atomic-path 6.1 workers concurrently for an extended rolling
window, because the two versions do not coordinate through the same primitive.
Drain or replace 6.0 stateful workers before activating 6.1 workers that share
the same replay backend.
