Replay protection
=================

A mathematically valid OTP or authentication proof can still be unsafe if
accepted twice. Calculation-only helpers remain available where interoperability
or enrollment checks need stateless behavior, while detailed verification paths
can use CacheLayer for atomic acceptance state.

Common configuration
--------------------

Replay-aware HOTP/TOTP/OCRA/MobileOTP use both of these values or neither:

* an integrity-protected, fail-closed, authoritative CacheLayer
  ``AuthenticationStateCacheInterface``; and
* a 1–190 byte, generation-specific ``factorId``.

AOTP always requires the CacheLayer state cache and factor ID because issuance
itself reserves a one-time challenge. GridOTP always requires CacheLayer because
its challenge/attempt/replay record is package-owned state. Passkey always uses
CacheLayer for short-lived registration/authentication ceremony state.

Supplying only part of an optional replay pair throws ``InvalidArgumentException``.
Unsafe cache policies and backend failures throw and must produce a temporary
authentication failure.

OTP 6.1 requires CacheLayer 3.3 or newer. Scalar replay transitions use the
native ``AtomicCacheProviderInterface`` capability when the configured backend
exposes it. Backends without atomics remain supported when they provide a
coordinated authentication-state lock. Native atomic failures never fall back to
locks after an operation has been selected.

``GenericOtp``, ``GridOTP``, and ``Passkey`` are intentionally lock-based because
their multi-field state transitions must remain serializable.

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
A backend without atomics uses the factor-specific coordinated lock path.

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

AOTP
----

AOTP issues a fresh challenge and reserves the exact canonical payload before
returning it:

.. code-block:: php

   $flowId = bin2hex(random_bytes(16));
   $context = 'login:web:' . $flowId;

   $challenge = $aotp->issue(
       cache: $stateCache,
       factorId: 'user-42:aotp:key-v1',
       context: $context,
   );

The state key binds factor ID plus the complete signed challenge. Modified
context, audience, nonce, issuance, or expiration therefore cannot reuse the
reservation. After signature verification, state transitions atomically from
unconsumed to consumed and the consumed marker remains through original expiry.

AOTP checks signature validity before returning ``Replay`` for consumed state.
An invalid signer therefore receives ``Mismatch`` rather than learning whether a
valid signer already consumed that challenge. Concurrent valid submissions still
produce exactly one success.

Replay protection does not make AOTP phishing resistant. ``AOTP::respond()``
requires independently trusted expected audience/context and refuses stale/future
challenges, but a real-time relay can still proxy a genuine challenge unless the
surrounding client/verifier flow independently binds the intended verifier and
local operation. See :doc:`aotp` and :doc:`security`.

GridOTP
-------

GridOTP challenge state contains the canonical challenge digest, remaining
attempts, absolute expiry, and consumed status. Verification mutates those fields
under one coordinated CacheLayer lock. A successful response consumes the
challenge; concurrent duplicates cannot both succeed. Wrong responses decrement
attempts without extending the original expiry.

Because GridOTP is a multi-field state machine, it does not switch to native
atomics even when the backend exposes them.

MobileOTP
---------

Replay-aware MobileOTP stores the greatest accepted 10-second timestep using the
same monotonic scalar state machinery as TOTP:

.. code-block:: php

   $result = $mobile->verifyWithWindow(
       otp: $submittedOtp,
       cache: $stateCache,
       factorId: 'user-42:mobile:secret-v1',
   );

Equal/older accepted timesteps are replay. The legacy verification window may be
widened explicitly, but replay state still moves only forward.

Passkey ceremonies
------------------

Passkey stores the complete registration/authentication options and ceremony
metadata under a random one-time ceremony ID. Successful completion marks the
ceremony consumed until its original expiry so duplicate valid browser responses
can be reported as replay rather than as a missing ceremony.

Passkey ceremony state is lock-based because type, options, binding, expiry, and
consumed state transition together. Durable WebAuthn ``CredentialRecord`` data is
not replay cache state and must remain in the application's authoritative durable
store.

Factor identity
---------------

A factor ID must distinguish account, protocol, suite/configuration, secret/key
generation, and any generation in which a moving counter can reset. Examples:

.. code-block:: text

   user-42:totp:secret-v3
   user-42:hotp:device-7:counter-v2
   merchant-9:ocra-signing:key-v5
   user-42:aotp:key-v2
   user-42:grid:secret-v2
   user-42:mobile:secret-v2

The raw factor ID is hashed into the package key. Hashing prevents direct
disclosure in backend key listings but does not make reuse safe. Change the ID
when a secret/key rotates, a suite changes, or a counter legitimately resets.

Passkey ceremony bindings are different: use flow-specific identifiers. Durable
credential identity comes from WebAuthn credential IDs.

Stateless verification
----------------------

``TOTP::verify()``, ``HOTP::verify()``, ``OCRA::verify()``, and MobileOTP's
non-cache verification path perform only protocol mathematics. This is useful
for test vectors, enrollment confirmation, or callers that implement an
equivalent atomic transition in a larger transaction. It is not single-use
protection by itself.

AOTP, GridOTP, GenericOtp, and Passkey ceremonies own issuance/acceptance state
and therefore use the configured CacheLayer path directly.

Concurrency and failures
------------------------

For every production backend/topology, test at least:

#. two concurrent equal matches produce one success and one replay;
#. a higher accepted moving factor prevents a later lower value;
#. different factor/key generations do not collide;
#. AOTP duplicate valid signatures consume one reservation exactly once;
#. GridOTP attempts/expiry/consumption remain serialized under concurrency;
#. Passkey duplicate ceremony completion succeeds at most once;
#. atomic contention is bounded and never regresses state;
#. an atomic backend failure never falls back to an unlocked or lock-based write;
#. lock fallback never writes after lock timeout or ownership loss;
#. malformed persisted state throws instead of becoming replay/miss;
#. read/write errors throw instead of becoming a cache miss; and
#. restart, failover, expiry, and eviction match each primitive's durability
   requirements.

Do not use ``Cache::memory`` for production authentication state: it coordinates
neither workers nor hosts and disappears on restart. Do not use
``Cache::remember()`` for these transitions because it does not express the
required compare/claim semantics.

Rolling upgrades from 6.0
-------------------------

OTP 6.0 coordinates existing replay mutations with locks. OTP 6.1 prefers native
atomics when available while keeping those existing replay keys and values. Do
not run stateful 6.0 and atomic-path 6.1 workers concurrently for an extended
rolling window, because the two versions do not coordinate through the same
primitive. Drain or replace 6.0 stateful workers before activating 6.1 workers
that share the same replay backend.
