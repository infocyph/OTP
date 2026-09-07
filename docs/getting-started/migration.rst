Migration and upgrade
=====================

OTP 6.1 keeps the existing HOTP/TOTP/OCRA/GenericOtp/recovery model introduced in
6.0 while upgrading the CacheLayer state engine and adding AOTP, GridOTP,
MobileOTP, and Passkey/WebAuthn. Migrate runtime coordination and application
persistence deliberately; changing code without understanding state ownership is
unsafe.

OTP 6.0 to 6.1
--------------

OTP 6.1 raises the CacheLayer floor to ``^3.3``. Public HOTP/TOTP/OCRA result
contracts and the package-owned existing v1 replay keys/values remain unchanged.
CacheLayer 3.3 native atomics are preferred for scalar replay transitions and a
coordinated lock is used when the configured backend does not expose atomics.
``GenericOtp`` remains lock-based.

Do not run shared stateful 6.0 and atomic-path 6.1 workers through a prolonged
rolling window. A 6.0 worker coordinates the existing scalar replay state by
lock while a 6.1 worker may mutate the same key by CAS. Drain or replace 6.0
stateful workers before activating 6.1 workers against that shared
authentication-state backend. This is a deployment-coordination rule, not a
replay-key migration: do not clear or rename the existing v1 replay state.

New in 6.1
----------

OTP 6.1 adds four independently namespaced authentication integrations:

* ``AOTP`` — Infocyph-defined Ed25519 asymmetric one-time challenge-response;
* ``GridOTP`` — Infocyph-defined dynamic-grid human knowledge factor;
* ``MobileOTP`` — compatibility with the established legacy Mobile-OTP/mOTP
  calculation; and
* ``Passkey`` — optional WebAuthn ceremony integration backed by
  ``web-auth/webauthn-lib``.

These do not replace existing TOTP/HOTP/OCRA factors automatically. Existing
application factor rows should remain on their current primitive until the
application intentionally enrolls a new factor type.

AOTP's 6.1 API deliberately requires a non-empty context for every issued
challenge. ``AOTP::respond()`` requires independently supplied
``expectedAudience`` and ``expectedContext`` values and checks challenge lifetime
before signing. Do not build those expected values by copying the received
challenge fields; derive them from trusted client configuration and locally known
operation/session state. See :doc:`../guides/aotp` before enabling AOTP.

Optional dependencies
---------------------

The base package does not require sodium or the WebAuthn library at runtime.
Composer configuration is:

* ``ext-sodium`` — ``require-dev`` + ``suggest``; required only for AOTP;
* ``web-auth/webauthn-lib:^5.3`` — ``require-dev`` + ``suggest``; required only
  for Passkey/WebAuthn.

Applications enabling Passkey install:

.. code-block:: bash

   composer require web-auth/webauthn-lib:^5.3

AOTP production images must enable ``ext-sodium``. ``AOTP::isAvailable()`` and
``Passkey::isAvailable()`` can be used for capability-gated feature exposure.
Passkey does not require ``ext-sodium`` from OTP.

Before upgrading
----------------

#. Inventory every use of Generic OTP, HOTP, TOTP, OCRA, recovery, enrollment,
   rotation, and replay APIs.
#. Record existing secret encoding, digits, algorithms, periods, counters,
   factor identifiers, and recovery batches.
#. Select one fail-closed, integrity-protected, authoritative CacheLayer backend;
   ensure it exposes native atomics or its coordinated state lock as required by
   each primitive.
#. Drain/replace 6.0 stateful workers before enabling 6.1 atomic-path workers on
   the same replay backend.
#. Deploy backend/schema/Redis changes before code that depends on them.
#. Test concurrent requests against the real production backing store/topology.
#. If adopting a new 6.1 primitive, add its application-owned durable schema
   before enabling enrollment.

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

HOTP and TOTP require at least 128 decoded secret bits and support 6–9 digits.
Persist HOTP ``nextCounter`` rather than ``matchedCounter``.

CacheLayer state migration
--------------------------

``OtpStoreInterface`` and ``ReplayStoreInterface`` were removed in 6.0. Pass a
CacheLayer ``AuthenticationStateCacheInterface`` capability and a
generation-specific factor ID directly to detailed HOTP/TOTP/OCRA verification.
The cache must be fail-closed, integrity-protected, and authoritative. OTP 6.1
uses a CacheLayer 3.3 atomic capability when available and otherwise requires
the cache's coordinated lock. ``GenericOtp`` always requires that lock. Unsafe
configurations are rejected before state is mutated, and authentication must
never turn backend errors into cache misses or credential results.

The existing package-owned SHA-256 v1 identifiers remain stable across 6.0 and
6.1. AOTP, GridOTP, MobileOTP, and Passkey introduce separate versioned state
domains and do not collide with old replay keys. Do not clear existing HOTP/TOTP
or OCRA replay state during the upgrade.

Verification results
--------------------

``VerificationResult`` continues to expose structured protocol outcomes such as
``Matched``, ``Drifted``, ``Resynchronized``, ``Malformed``, ``Mismatch``, and
``Replay``. AOTP, GridOTP, and MobileOTP reuse that result model. Passkey uses
``PasskeyResult`` because successful WebAuthn ceremonies also return the durable
credential record that the application must persist.

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
include flags. HOTP always emits ``counter``. The generic parser returns
effective defaults and preserves unknown extension values:

.. code-block:: php

   $parsed = \Infocyph\OTP\Support\ProvisioningUriParser::parse($uri);

Labels are account values without an issuer prefix. Pass the issuer separately.
Reserved query names are case-sensitive in imported URIs and collisions in
additional parameters are rejected case-insensitively.

``otpauth://`` provisioning does not apply to AOTP, GridOTP, MobileOTP, or
Passkey/WebAuthn.

Application-owned persistence for new 6.1 primitives
----------------------------------------------------

* AOTP: persist the public key, factor generation, audience, status/revocation;
  keep the private key on the client/device.
* GridOTP: persist the enrolled secret encrypted and use a generation-specific
  factor ID.
* MobileOTP: persist the Init-Secret and PIN encrypted; preserve the exact secret
  character case.
* Passkey: persist serialized ``CredentialRecord`` data in an authoritative
  durable store and save the updated record after every successful assertion.

CacheLayer owns only package challenge/replay state, not these durable factor
records.

Rollout strategy
----------------

For a zero-downtime application migration between factor generations, deploy new
store schemas first, enroll new factor generations explicitly, keep replay/factor
IDs distinct, and remove the old path only after the application-defined overlap
or migration completes. For the 6.0-to-6.1 runtime upgrade specifically, follow
the drain/replace rule above rather than concurrently mixing lock-based 6.0
workers with atomic-path 6.1 workers on the same replay state.
