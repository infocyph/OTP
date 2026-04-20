Secret Rotation and Reprovisioning
==================================

Overview
--------

Secret rotation is partly implemented as helper primitives.

Current package support:

- TOTP exposes ``rotateSecret()`` for simple overlap planning
- TOTP, HOTP, and OCRA now expose ``planSecretRotation()``
- rotation planning can include a reprovisioning payload for the replacement secret

This is still intentionally lightweight. The package does not persist secret versions for you.

TOTP rotation planning
----------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $totp = (new TOTP(TOTP::generateSecret()))
       ->setAlgorithm('sha256');

   $rotation = $totp->planSecretRotation(
       TOTP::generateSecret(),
       label: 'alice@example.com',
       issuer: 'Example App',
       gracePeriodInSeconds: 3600,
       withQrSvg: true,
   );

   $rotation->currentSecret;
   $rotation->nextSecret;
   $rotation->overlapUntil;
   $rotation->hasGracePeriod();
   $rotation->isDualSecretActive();
   $rotation->nextEnrollment?->uri;
   $rotation->nextEnrollment?->qrSvg;

HOTP rotation planning
----------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\HOTP;

   $hotp = (new HOTP(HOTP::generateSecret()))
       ->setCounter(12)
       ->setAlgorithm('sha512');

   $rotation = $hotp->planSecretRotation(
       HOTP::generateSecret(),
       label: 'alice@example.com',
       issuer: 'Example App',
   );

   $rotation->requiresImmediateCutover();
   $rotation->nextEnrollment?->uri;

The replacement payload keeps the current HOTP counter configuration so the reprovisioned device starts from the expected server-side state.

OCRA rotation planning
----------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\OCRA;

   $ocra = new OCRA(
       'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
       '12345678901234567890123456789012',
   );

   $rotation = $ocra->planSecretRotation(
       'abcdefghijklmnopqrstuvwxyz123456',
       label: 'alice@example.com',
       issuer: 'Example App',
       gracePeriodInSeconds: 900,
   );

   $rotation->nextEnrollment?->uri;

Recommended application flow
----------------------------

1. Generate the replacement secret.
2. Persist it as a new secret version or record.
3. Decide whether the old secret remains valid temporarily.
4. Reprovision the user with the new enrollment payload or QR.
5. Mark the old secret retired after the grace window closes.

What still belongs to the application
-------------------------------------

- storing secret versions durably
- deciding how dual-secret verification works during the overlap window
- retiring the old secret at cutover time
- auditing who initiated the rotation and when
