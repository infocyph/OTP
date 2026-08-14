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

The first three are successful reasons. Replay means the cryptographic value
matched but state rejected reuse; ``matched`` is false.

VerificationResult
------------------

Fields:

.. code-block:: php

   $result->matched;          // bool
   $result->reason;           // VerificationReason
   $result->matchedTimestep;  // ?int, TOTP or time-drifted OCRA
   $result->matchedCounter;   // ?int, HOTP/counter OCRA
   $result->nextCounter;      // ?int
   $result->driftOffset;      // int
   $result->replayDetected;   // bool
   $result->verifiedAt;       // ?DateTimeImmutable

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

``isDrifted()`` also applies to HOTP resynchronization because it checks successful
non-zero offset, while ``reason`` identifies protocol-specific semantics.

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
period.

VerificationWindow
------------------

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $exact = new VerificationWindow();
   $asymmetric = new VerificationWindow(past: 2, future: 1);
   $symmetric = VerificationWindow::symmetric(2);

Past and future values are non-negative and their sum cannot exceed 100.

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
