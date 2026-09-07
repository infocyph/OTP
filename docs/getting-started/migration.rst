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

Old generic calls from pre-6.0 designs such as:

.. code-block:: php

   $otp = new OTP(...);
   $code = $otp->getOTP($binding);

use the 6.x API:

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
delete-on-any-attempt behavior, and bulk flush are not part of the current
model. ``GenericOtp`` stores its versioned record directly in CacheLayer and
performs comparison, consumption, failed-attempt decrement, expiry cleanup, and
scoped deletion under a CacheLayer lock.

HOTP and TOTP
-------------

Algorithm, digit, and period configuration is constructor-only. HOTP does not
own a mutable application counter:

.. code-block:: php

   $hotp = new \Infocyph\OTP\HOTP($secret, digits: 6, algorithm: 'sha1');
   $result = $hotp->verifyWithResult($submitted, $storedCounter, lookAhead: 10);

   if ($result->matched) {
       $storedCounter = $result->nextCounter;
   }

HOTP and TOTP require at least 128 decoded secret bits and support 6–9 digits.
Persist HOTP ``nextCounter`` rather than ``matchedCounter``.

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

Every suite-required value must be present and irrelevant values must be absent.
Use ``OCRA::fromBase32()`` for enrolled Base32 secrets. Session input is UTF-8;
use ``OCRA::sessionHex()`` only when an integration represents valid UTF-8
session data as hexadecimal. Truncated suites allow 4–9 digits; ``t=0`` returns
a full uppercase hexadecimal HMAC.

CacheLayer state upgrade
------------------------

``OtpStoreInterface`` and ``ReplayStoreInterface`` from older designs are not
used. Pass a CacheLayer ``AuthenticationStateCacheInterface`` capability and a
generation-specific factor ID directly to detailed HOTP/TOTP/OCRA/MobileOTP
verification. AOTP receives the cache and factor ID at issue/verify time;
GridOTP owns the cache in its constructor; Passkey owns the cache and uses a
flow-specific binding.

The cache must be fail-closed, integrity-protected, and authoritative. OTP 6.1
uses CacheLayer 3.3 atomics where the transition is scalar and otherwise uses the
coordinated lock. ``GenericOtp``, ``GridOTP``, and ``Passkey`` always require the
lock because their state is multi-field. Unsafe configurations are rejected
before state mutation, and backend errors are never converted into cache misses
or credential results.

The existing package-owned SHA-256 v1 identifiers remain stable for carried-
forward 6.0 HOTP/TOTP/OCRA/GenericOtp state. New AOTP, GridOTP, MobileOTP, and
Passkey namespaces are separate and cannot collide with those existing keys.

Never reset HOTP or counter-OCRA monotonic state under an existing factor ID.
TOTP state may expire after its acceptance window. Non-counter OCRA requires an
explicit replay TTL. Old PSR-6 Generic OTP entries from pre-6.0 designs are not
read or reused.

Adopting AOTP
-------------

AOTP requires a new application factor type containing at least:

* generation-specific factor ID;
* Ed25519 public key;
* trusted audience; and
* enrollment/status metadata.

The private key belongs on the client/device and should never be migrated into
verifier storage. Enroll a fresh key pair rather than converting a TOTP/OCRA
shared secret. Rotate factor ID whenever the key pair changes.

See :doc:`../guides/aotp` for complete enrollment and authentication code.

Adopting GridOTP
----------------

GridOTP requires a new encrypted verifier secret using its 32-symbol alphabet.
Do not derive the GridOTP secret from an existing TOTP/HOTP/OCRA secret or user
password. Enroll a fresh generated secret and give it a generation-specific
factor ID.

GridOTP challenge state is new and short-lived; there is no old replay state to
migrate. See :doc:`../guides/grid-otp`.

Adopting MobileOTP
------------------

MobileOTP is intended for existing mOTP interoperability. Migrating an existing
mOTP factor requires preserving the exact 16-hex-character Init-Secret text and
its four-digit PIN because both are verifier inputs and the Init-Secret's
character case affects the legacy calculation.

Do not reinterpret the Init-Secret as decoded binary or as Base32. Give the
migrated factor a generation-specific MobileOTP factor ID and enable CacheLayer
replay state independently. Prefer a zero verification window unless legacy
clients require a wider tolerance. See :doc:`../guides/mobile-otp`.

Adopting Passkey/WebAuthn
------------------------

Passkey requires new durable application storage for WebAuthn credentials. Store
at minimum the application user/factor relationship, credential ID, serialized
``CredentialRecord``, status/revocation metadata, and audit timestamps required
by your product.

Do not attempt to convert OTP shared secrets into Passkey credentials. A browser
or authenticator must perform a new WebAuthn registration ceremony. OTP's
CacheLayer state stores only the short-lived ceremony; the resulting
``CredentialRecord`` belongs in the authoritative application database.

After every successful assertion, persist the updated ``credentialRecordJson``
returned by ``PasskeyResult``. There is no ``rpName`` constructor argument; OTP
uses the configured RP ID as the serialized RP display name. See
:doc:`../guides/passkey` for complete browser/server flows.

Verification results
--------------------

``VerificationReason`` enum cases include:

.. code-block:: php

   use Infocyph\OTP\VerificationReason;

   if ($result->reason === VerificationReason::Replay) {
       // ...
   }

``VerificationResult`` remains the detailed result for HOTP/TOTP/OCRA and is also
used by AOTP, GridOTP, and MobileOTP. Passkey uses ``PasskeyResult`` because a
successful assertion must return the durable updated WebAuthn credential record.
See :doc:`../api/results`.

Provisioning
------------

HOTP/TOTP convenience methods infer required/default parameters. The generic
parser returns effective defaults and preserves unknown extension values:

.. code-block:: php

   $parsed = \Infocyph\OTP\Support\ProvisioningUriParser::parse($uri);

Labels are account values without an issuer prefix. Pass the issuer separately.
Reserved query names are case-sensitive in imported URIs and collisions in
additional parameters are rejected case-insensitively.

AOTP, GridOTP, MobileOTP, and Passkey do not use ``otpauth://`` provisioning.
AOTP/GridOTP use their value-object transport, MobileOTP follows its legacy
client enrollment model, and Passkey uses WebAuthn browser ceremonies.

Removed workflow helpers
------------------------

The package does not own:

* step-up policy or step-up result objects;
* device enrollment workflow state;
* general secret persistence abstractions;
* a generic abstract authenticator;
* OTP-specific cache/store adapters;
* custom replay-store abstractions; or
* bulk state flushing.

Move these responsibilities into the application, where policy, persistence,
authorization, and audit context are available.

Rollout strategy
----------------

For the 6.0→6.1 runtime upgrade, follow the drain/replace rule rather than
concurrently mixing lock-based 6.0 workers with atomic-path 6.1 workers on the
same existing replay state.

For new factor types, deploy durable application schema/configuration first,
then enable enrollment, then authentication. Keep every secret/key generation on
a distinct factor ID. Passkey ceremonies use flow-specific bindings and durable
credential IDs instead of factor replay IDs.

Do not clear the authentication-state namespace during release deployment.
Challenge/replay records should expire or advance according to their protocol
rules.
