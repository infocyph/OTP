Results and value objects
=========================

All result and value objects are immutable ``final readonly`` classes.

VerificationReason
------------------

``Infocyph\OTP\VerificationReason`` is a string-backed enum:

.. code-block:: php

   VerificationReason::Matched;        // "matched"
   VerificationReason::Drifted;        // "drifted"
   VerificationReason::Resynchronized; // "resynchronized"
   VerificationReason::Malformed;      // "malformed"
   VerificationReason::Mismatch;       // "mismatch"
   VerificationReason::Replay;         // "replay"

The first three are successful reasons. Replay means cryptographic/protocol
verification reached an already-consumed or already-advanced state;
``matched`` is false.

VerificationResult
------------------

``VerificationResult`` is returned by detailed HOTP/TOTP/OCRA/AOTP/GridOTP/
MobileOTP verification methods.

Fields:

.. code-block:: php

   $result->matched;          // bool
   $result->reason;           // VerificationReason
   $result->matchedTimestep;  // ?int, TOTP/MobileOTP/time-drifted OCRA
   $result->matchedCounter;   // ?int, HOTP/counter OCRA
   $result->nextCounter;      // ?int
   $result->driftOffset;      // int
   $result->replayDetected;   // bool
   $result->verifiedAt;       // ?DateTimeImmutable

AOTP and GridOTP use the same result type but normally populate only
``matched``, ``reason``, ``replayDetected``, and ``verifiedAt``. MobileOTP uses
``matchedTimestep`` and ``driftOffset`` like a ten-second time-based protocol.

A result never contains both timestep and counter. ``Matched`` has zero drift;
``Drifted`` has a timestep, no counter, and non-zero drift;
``Resynchronized`` has a counter and positive drift. For a matched counter below
``PHP_INT_MAX``, ``nextCounter`` is exactly the immediate successor; at integer
exhaustion it is null.

Helpers:

.. code-block:: php

   if ($result->isExact()) {
       // Successful match with zero drift.
   }

   if ($result->isDrifted()) {
       // Successful match with a non-zero offset.
   }

``isDrifted()`` also applies to HOTP resynchronization because it checks
successful non-zero offset, while ``reason`` identifies protocol-specific
semantics.

Factory methods
---------------

The public factories preserve invariants:

.. code-block:: php

   VerificationResult::malformed();
   VerificationResult::mismatch();
   VerificationResult::replay(
       matchedTimestep: $step,
       driftOffset: -1,
   );
   VerificationResult::success(
       reason: VerificationReason::Matched,
       matchedTimestep: $step,
   );

Most applications consume results returned by protocol classes rather than
constructing them.

PasskeyResult
-------------

Passkey/WebAuthn uses a dedicated result because successful authentication must
return the durable WebAuthn credential record that may have changed during
verification.

.. code-block:: php

   $result->matched;               // bool
   $result->reason;                // VerificationReason
   $result->credentialId;          // ?string, URL-safe Base64
   $result->credentialRecordJson;  // ?string, sensitive durable record
   $result->userHandle;            // ?string, URL-safe Base64, sensitive
   $result->replayDetected;        // bool

A successful result always uses ``VerificationReason::Matched`` and contains a
credential ID plus serialized ``CredentialRecord``. Persist
``credentialRecordJson`` after registration and overwrite the old durable record
after every successful authentication.

Failure factories are ``malformed()``, ``mismatch()``, and ``replay()``.
``replay()`` sets ``replayDetected`` to true. Debug output redacts credential
record JSON and user handle.

AotpKeyPair
-----------

``AOTP::generateKeyPair()`` returns:

.. code-block:: php

   $keys->publicKey;  // URL-safe Base64 Ed25519 public key
   $keys->privateKey; // URL-safe Base64 Ed25519 private key, sensitive

The public key represents 32 bytes and the private key 64 bytes before encoding.
Debug output always redacts the private key. The verifier should persist only the
public key; the private key belongs on the client/device.

AotpChallenge
-------------

.. code-block:: php

   $challenge->id;        // 128-bit random ID, URL-safe Base64
   $challenge->nonce;     // 256-bit random nonce, URL-safe Base64
   $challenge->audience;  // verifier audience
   $challenge->context;   // optional operation context
   $challenge->issuedAt;  // Unix timestamp
   $challenge->expiresAt; // Unix timestamp

Transport helpers:

.. code-block:: php

   $array = $challenge->toArray();
   $challenge = AotpChallenge::fromArray($array);
   $payload = $challenge->signingPayload();

``signingPayload()`` is the canonical binary payload covered by the Ed25519
signature. Debug output redacts nonce and non-empty context.

AotpResponse
------------

.. code-block:: php

   $response->challengeId; // challenge identifier
   $response->signature;   // URL-safe Base64 detached Ed25519 signature

``toArray()`` and ``fromArray()`` provide transport round-tripping. The signature
represents exactly 64 bytes before URL-safe Base64 encoding.

GridChallenge
-------------

.. code-block:: php

   $challenge->id;           // 128-bit random ID, URL-safe Base64
   $challenge->grid;         // symbol => decimal-label mapping
   $challenge->positions;    // list<int>, one-based positions in response order
   $challenge->secretLength; // 8..32
   $challenge->issuedAt;
   $challenge->expiresAt;

Transport and integrity helpers:

.. code-block:: php

   $array = $challenge->toArray();
   $challenge = GridChallenge::fromArray($array);
   $payload = $challenge->canonicalPayload();

The grid contains the complete 32-symbol secret alphabet and its response labels
are balanced so each decimal digit occurs three or four times. Debug output
redacts the grid and requested positions.

PasskeyCeremony
---------------

A Passkey registration/authentication start returns a ``PasskeyCeremony``:

.. code-block:: php

   $ceremony->id;          // random 128-bit ceremony ID, URL-safe Base64
   $ceremony->type;        // registration or authentication
   $ceremony->optionsJson; // sensitive serialized WebAuthn options
   $ceremony->expiresAt;   // absolute Unix timestamp

The browser receives the options and ceremony ID. OTP separately stores the
complete options in integrity-protected CacheLayer ceremony state so finish calls
do not trust caller-supplied replacement options.

RecoveryCodeGenerationResult
----------------------------

.. code-block:: php

   $batch->plainCodes;      // list<string>
   $batch->totalGenerated;  // int
   $batch->remainingCount;  // int
   $batch->lastUsedAt;      // ?DateTimeImmutable

``plainCodes`` is the only plaintext recovery-code copy. Display it once and do
not log or persist it in recoverable form.

RecoveryCodeConsumptionResult
-----------------------------

.. code-block:: php

   $result->consumed;       // bool
   $result->remainingCount; // int
   $result->totalGenerated; // int
   $result->lastUsedAt;     // ?DateTimeImmutable

Counts and timestamp originate from the store's same committed consume mutation
for validly shaped input. Invalid input uses independent metadata lookup and
returns ``consumed === false``. Impossible custom-store state—negative counts,
remaining above total, wrong types, or successful consumption without a
timestamp—throws ``RuntimeException``.

EnrollmentPayload
-----------------

.. code-block:: php

   $payload->secret; // string
   $payload->uri;    // string
   $payload->issuer; // string
   $payload->label;  // string
   $payload->qrSvg;  // ?string

Secret, URI, and SVG are sensitive. ``qrSvg`` is present only when requested.

ParsedOtpAuthUri
----------------

.. code-block:: php

   $parsed->type;                 // hotp, totp, ocra
   $parsed->secret;               // normalized Base32
   $parsed->label;
   $parsed->issuer;               // ?string
   $parsed->algorithm;            // normalized lowercase
   $parsed->digits;
   $parsed->period;               // TOTP only
   $parsed->counter;              // HOTP only
   $parsed->ocraSuite;            // OCRA only
   $parsed->additionalParameters; // array<string,string>

Parser defaults are materialized: SHA-1, six digits, and a 30-second TOTP
period. AOTP, GridOTP, MobileOTP, and Passkey intentionally do not use
``otpauth://`` provisioning.

VerificationWindow
------------------

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $exact = new VerificationWindow();
   $asymmetric = new VerificationWindow(past: 2, future: 1);
   $symmetric = VerificationWindow::symmetric(2);

Past and future values are non-negative and their sum cannot exceed 100. A
protocol may impose a tighter bound; MobileOTP caps each direction at 18 steps.

OcraSuite
---------

``OcraSuite::parse()`` returns the authoritative parsed suite:

.. code-block:: php

   $suite->suite;
   $suite->algorithm;
   $suite->digits;
   $suite->counterEnabled;
   $suite->challengeFormat;
   $suite->challengeLength;
   $suite->pinAlgorithm;
   $suite->sessionLength;
   $suite->timeStepSeconds;

   $suite->usesPin();
   $suite->usesSession();
   $suite->usesTime();

SecretRotation
--------------

.. code-block:: php

   $rotation->currentSecret;
   $rotation->nextSecret;
   $rotation->overlapUntil;   // ?DateTimeImmutable, exclusive
   $rotation->nextEnrollment; // ?EnrollmentPayload

   $rotation->hasGracePeriod();
   $rotation->isDualSecretActive();
   $rotation->requiresImmediateCutover();

The object validates canonical strong, distinct Base32 secrets and consistency
between replacement secret and optional enrollment payload.
