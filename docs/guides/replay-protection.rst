Replay protection
=================

A mathematically or cryptographically valid credential can still be unsafe if it
is accepted twice. OTP 6.1 uses CacheLayer 3.3 for package-owned one-time and
monotonic authentication state.

Common configuration
--------------------

For replay-aware HOTP/TOTP/OCRA/MobileOTP calls, pass both values or neither:

* an integrity-protected, fail-closed, authoritative CacheLayer
  ``AuthenticationStateCacheInterface``; and
* a 1–190 byte generation-specific ``factorId``.

Supplying only part of that pair throws ``InvalidArgumentException``. AOTP also
uses a generation-specific factor ID, but its cache is passed directly to
``issue()``/``verify*()``. GridOTP owns the cache in its constructor and takes a
factor ID when issuing/verifying. Passkey owns the cache in its constructor and
uses a flow-specific ``binding`` plus random ceremony ID rather than a durable
factor ID for ceremony state.

Unsafe cache policies and backend failures throw and must produce a temporary
authentication failure.

OTP 6.1 requires CacheLayer 3.3 or newer. Scalar replay transitions prefer the
native ``AtomicCacheProviderInterface`` capability when the configured backend
exposes it. Backends without atomics remain supported when they provide a
coordinated authentication-state lock. Native atomic failures never fall back to
locks after the atomic path has been selected.

``GenericOtp``, ``GridOTP``, and ``Passkey`` are intentionally lock-based because
their multi-field state must transition as one serializable unit.

See :doc:`storage` for complete backend requirements.

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
A backend without atomics uses the factor-specific coordinated lock fallback.

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

The claim identity is derived from the complete authenticated OCRA message. The
application-supplied TTL is mandatory. For time suites it must cover the complete
accepted time window. Atomic-capable backends use a one-time ``setIfAbsent``
claim; the lock fallback provides equivalent single-use behavior.

AOTP
----

AOTP is inherently stateful because a verifier must first reserve an issued
challenge and then consume exactly that reservation after signature validation:

.. code-block:: php

   $challenge = $aotp->issue(
       cache: $stateCache,
       factorId: 'user-42:aotp:key-v2',
       context: 'login:web',
   );

   $result = $aotp->verifyWithResult(
       cache: $stateCache,
       factorId: 'user-42:aotp:key-v2',
       challenge: $submittedChallenge,
       response: $submittedResponse,
   );

The reservation key is derived from the complete canonical challenge, including
ID, nonce, audience, context, issue time, and expiration. Tampering with those
fields therefore cannot find the original reservation.

The state starts unconsumed and a valid signature atomically transitions it to
consumed. Exactly one concurrent valid verifier can succeed; a later duplicate
returns ``VerificationReason::Replay``. The consumed marker remains until the
challenge's original expiration.

GridOTP
-------

GridOTP uses a coordinated lock for the complete challenge state rather than a
single scalar replay claim:

.. code-block:: php

   $gridOtp = new \Infocyph\OTP\GridOTP(
       cache: $stateCache,
       secret: $secret,
       maxAttempts: 3,
   );

   $challenge = $gridOtp->issue('user-42:grid:secret-v2');
   $result = $gridOtp->verifyWithResult(
       'user-42:grid:secret-v2',
       $submittedChallenge,
       $submittedResponse,
   );

The state binds a digest of the complete challenge, remaining attempts, absolute
expiry, and consumed status. A wrong well-formed response decrements attempts.
Success changes the same record to consumed. That multi-field mutation is always
serialized by CacheLayer's coordinated lock; it is not decomposed into separate
atomic operations.

The consumed marker remains until original expiry, so a duplicate valid response
can be reported as replay. A response captured for one dynamic grid cannot be
used against another challenge.

MobileOTP
---------

Replay-aware MobileOTP uses the same greatest-accepted-timestep rule as TOTP,
but the protocol period is 10 seconds:

.. code-block:: php

   $result = $mobile->verifyWithWindow(
       otp: $submittedOtp,
       window: new VerificationWindow(past: 1, future: 1),
       cache: $stateCache,
       factorId: 'user-42:mobile:secret-v2',
   );

The TTL is ``10 * (past + future + 1)`` seconds. Once a timestep is accepted,
equal or lower accepted candidates cannot succeed for that factor generation.
The protocol permits windows up to 18 steps in each direction for legacy
compatibility, but use the smallest window the deployment actually needs.

Passkey ceremonies
------------------

Passkey/WebAuthn signatures and authenticator counters are validated by
``web-auth/webauthn-lib``. OTP additionally makes each registration or
authentication ceremony one-time at the application boundary.

.. code-block:: php

   $binding = 'login-flow-9af3';
   $ceremony = $passkey->beginAuthentication($binding);

   $result = $passkey->finishAuthentication(
       binding: $binding,
       ceremonyId: $submittedCeremonyId,
       credentialRecordJson: $storedCredentialRecord,
       credentialJson: $browserCredentialJson,
   );

The server stores ceremony type, complete serialized request/creation options,
optional user handle, absolute expiry, and consumed status under a random 128-bit
ceremony ID. The entire record is lock-coordinated. A successful ceremony is
marked consumed through its original TTL so concurrent/repeated assertions are
reported as replay.

Passkey durable ``CredentialRecord`` data is not replay cache. Persist the
updated record returned after successful authentication because authenticator
counter/backup/verification state may have changed.

Factor and flow identity
------------------------

A factor ID must distinguish account, protocol, suite/configuration, secret/key
generation, and any generation in which a moving counter can reset. Examples:

.. code-block:: text

   user-42:totp:secret-v3
   user-42:hotp:device-7:counter-v2
   merchant-9:ocra-signing:key-v5
   user-42:aotp:key-v2
   user-42:grid:secret-v2
   user-42:mobile:secret-v2

The raw factor ID is hashed into package keys. Hashing prevents direct disclosure
in backend key listings but does not make reuse safe. Change the ID when a
secret/key rotates, a suite changes, a MobileOTP secret/PIN generation changes,
or a counter legitimately resets.

Passkey ``binding`` is different: it identifies the specific registration/login
flow. Make it flow-specific and bind it server-side to the intended account or
pre-authentication session. Durable passkey identity comes from WebAuthn
credential IDs, not the ceremony binding.

Stateless verification
----------------------

``TOTP::verify()``, ``HOTP::verify()``, ``OCRA::verify()``, and
``MobileOTP::verify()`` can perform protocol verification without package replay
state. This is appropriate for test vectors, enrollment confirmation, or a caller
that performs an equivalent atomic transition in a larger transaction. It is not
single-use protection by itself.

AOTP, GridOTP, and Passkey are challenge/ceremony protocols whose normal
verification path is stateful by design.

Concurrency and failures
------------------------

For every production backend, test at least:

#. two concurrent equal TOTP/HOTP/OCRA/MobileOTP matches produce one acceptance
   where the protocol/state policy promises single use;
#. two concurrent valid AOTP submissions produce exactly one success and one
   replay;
#. GridOTP attempts and consumption cannot race under its lock;
#. a successful Passkey ceremony cannot be accepted twice;
#. a higher accepted moving factor prevents a later lower value;
#. different factor/key generations do not collide;
#. atomic contention is bounded and never regresses state;
#. an atomic backend failure never falls back to an unlocked or lock-based write;
#. lock fallback never writes after lock timeout or ownership loss;
#. malformed persisted state throws instead of becoming replay/miss;
#. read/write/delete errors throw instead of becoming a cache miss; and
#. restart, failover, expiry, and eviction match each primitive's durability
   requirements.

Do not use ``Cache::memory`` for production authentication state. Do not use
``Cache::remember()`` for these transitions because it does not express the
required compare/claim/multi-field semantics.

Rolling upgrades from 6.0
-------------------------

OTP 6.0 coordinates the existing HOTP/TOTP/OCRA replay mutations with locks. OTP
6.1 prefers native atomics when available while keeping those existing replay
keys and values. Do not run stateful 6.0 and atomic-path 6.1 workers concurrently
for an extended rolling window because the two versions do not coordinate
through the same primitive. Drain or replace 6.0 stateful workers before
activating 6.1 workers that share the same replay backend.

AOTP, GridOTP, MobileOTP, and Passkey use independently namespaced state added in
6.1, so they do not collide with carried-forward HOTP/TOTP/OCRA/GenericOtp state.
