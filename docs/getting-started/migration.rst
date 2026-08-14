Major-version migration
=======================

This release intentionally has no compatibility layer. Migrate behavior and
durable state together; changing method names without changing storage
semantics is unsafe.

Before upgrading
----------------

#. Inventory every use of the old ``OTP``, HOTP, TOTP, OCRA, recovery, enrollment,
   step-up, secret-store, and replay APIs.
#. Record the existing secret encoding, digits, algorithms, periods, counters,
   factor identifiers, and recovery batches.
#. Select one authoritative CacheLayer backend with its configured state lock.
#. Deploy backend/schema/Redis changes before code that depends on them.
#. Test concurrent requests against the real backing store.
#. Plan how old factor IDs and replay state will be retired.

Generic OTP
-----------

Old generic calls:

.. code-block:: php

   $otp = new OTP(...);
   $code = $otp->getOTP($binding);

Become:

.. code-block:: php

   use Infocyph\OTP\GenericOtp;

   $otp = new GenericOtp(
       cache: $stateCache,
       key: $purposeSpecificHmacKey,
       digits: 6,
       ttlSeconds: 300,
       maxAttempts: 3,
   );
   $code = $otp->generate($binding);

Custom generic-OTP stores, direct PSR cache injection, unkeyed hashes,
delete-on-any-attempt behavior, and bulk flush were removed. ``GenericOtp`` now
stores its versioned record directly in CacheLayer and performs comparison,
consumption, failed-attempt decrement, expiry cleanup, and scoped deletion under
a CacheLayer lock.

HOTP and TOTP
-------------

Algorithm, digit, and period configuration is constructor-only. HOTP no longer
owns a mutable counter:

.. code-block:: php

   $hotp = new \Infocyph\OTP\HOTP($secret, digits: 6, algorithm: 'sha1');
   $result = $hotp->verifyWithResult($submitted, $storedCounter, lookAhead: 10);

   if ($result->matched) {
       $storedCounter = $result->nextCounter;
   }

HOTP and TOTP now require at least 128 decoded secret bits and support 6–9
digits. Persist HOTP ``nextCounter`` rather than ``matchedCounter``.

CacheLayer state migration
--------------------------

``OtpStoreInterface`` and ``ReplayStoreInterface`` were removed. Pass a
CacheLayer's ``AuthenticationStateCacheInterface`` capability and a
generation-specific factor ID directly to detailed HOTP/TOTP/OCRA verification.
The cache must be fail-closed, integrity-protected, authoritative, and expose
its configured state lock; unsafe configurations are rejected before state is
read. Authentication must never turn backend errors into cache misses.

The new keys are package-owned SHA-256 identifiers, so old custom-store rows do
not migrate by renaming. During rollout, either require fresh Generic OTP
issuance and fresh protocol verification state, or perform an application-owned
one-time migration before enabling the new verifier. Never reset HOTP or
counter-OCRA monotonic state under an existing factor ID. TOTP state may expire
after its acceptance window. Non-counter OCRA requires an explicit replay TTL.
Old PSR-6 Generic OTP entries are intentionally not read or reused. If seamless
continuity matters, stop issuing through the old version, wait for every active
challenge TTL to elapse, and only then cut verification over to CacheLayer.

Verification results
--------------------

String reasons were replaced by ``VerificationReason`` enum cases:

.. code-block:: php

   use Infocyph\OTP\VerificationReason;

   if ($result->reason === VerificationReason::Replay) {
       // ...
   }

Detailed results now expose protocol-specific ``matchedTimestep``,
``matchedCounter``, ``nextCounter``, ``driftOffset``, ``replayDetected``, and
``verifiedAt`` fields.

OCRA
----

The suite is parsed once and is authoritative. Counter, PIN, session, timestamp,
and challenge values are operation arguments:

.. code-block:: php

   $ocra = new \Infocyph\OTP\OCRA($suite, $rawKey);
   $response = $ocra->generate(
       challenge: $challenge,
       counter: $counter,
       pin: $pin,
       session: $session,
       timestamp: $timestamp,
   );

Every suite-required value must be present and every irrelevant value must be
absent. Use ``OCRA::fromBase32()`` for an enrolled Base32 secret. Session input is
UTF-8 data; use ``OCRA::sessionHex()`` only when an integration represents its
valid UTF-8 session value as hexadecimal. Truncated suites allow 4–9 digits;
``t=0`` returns a full uppercase hexadecimal HMAC.

Provisioning
------------

Convenience methods infer required/default parameters and no longer expose
include flags. HOTP always emits ``counter``. The generic parser now returns
effective defaults and preserves unknown extension values:

.. code-block:: php

   $parsed = \Infocyph\OTP\Support\ProvisioningUriParser::parse($uri);

Labels are account values without an issuer prefix. Pass the issuer separately.
Reserved query names are case-sensitive in imported URIs and collisions in
additional parameters are rejected case-insensitively.

Removed workflow helpers
------------------------

The package no longer owns:

* step-up policy or step-up result objects;
* device enrollment workflow state;
* secret persistence abstractions;
* a generic abstract authenticator;
* OTP-specific cache/store adapters;
* custom replay-store abstractions; or
* bulk state flushing.

Move these responsibilities into the application, where policy, persistence,
authorization, and audit context are available.

Rollout strategy
----------------

For a zero-downtime upgrade, deploy new store schemas first, dual-read only at
the application persistence boundary if necessary, migrate each factor to a
versioned factor ID, and remove the old path after all active records are
converted. Never share a replay key between old and new secret generations.
