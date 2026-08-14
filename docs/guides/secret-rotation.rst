Secret rotation
===============

HOTP, TOTP, and OCRA expose ``planRotation()``. It validates a replacement secret
and creates optional enrollment material. It does not persist, activate,
verify, schedule, or revoke anything.

Create a TOTP rotation plan
---------------------------

.. code-block:: php

   use Infocyph\OTP\TOTP;

   $rotation = $totp->planRotation(
       newSecret: TOTP::generateSecret(),
       label: 'alice@example.com',
       issuer: 'Example App',
       gracePeriodInSeconds: 300,
       now: null,
       additionalParameters: ['tenant' => 'north'],
       withQrSvg: true,
       imageSize: 256,
   );

The result exposes:

.. code-block:: php

   $rotation->currentSecret;
   $rotation->nextSecret;
   $rotation->overlapUntil;
   $rotation->nextEnrollment;

   $rotation->hasGracePeriod();
   $rotation->isDualSecretActive();
   $rotation->requiresImmediateCutover();

``overlapUntil`` is an exclusive boundary. At exactly that instant, the old
secret is no longer active.

Immediate cutover
-----------------

Null and zero grace periods both mean immediate cutover:

.. code-block:: php

   $rotation = $totp->planRotation(
       TOTP::generateSecret(),
       'alice@example.com',
       'Example App',
       gracePeriodInSeconds: 0,
   );

   assert($rotation->requiresImmediateCutover());
   assert($rotation->overlapUntil === null);

Use immediate cutover after compromise when continued acceptance of the old
secret is unsafe.

Grace-period rollout
--------------------

A safe application workflow is:

#. persist the next secret encrypted as a pending generation;
#. assign it a new factor ID;
#. show ``nextEnrollment`` through an authenticated response;
#. verify proof using an object constructed from ``nextSecret``;
#. activate the next generation;
#. during grace, try the new generation first and then the old generation;
#. maintain independent replay state for both generations;
#. stop accepting the old generation at ``overlapUntil``; and
#. erase old secret and replay state after audit/retention requirements permit.

Do not infer activation from the existence of a plan.

HOTP rotation
-------------

HOTP adds an explicit replacement counter:

.. code-block:: php

   $rotation = $hotp->planRotation(
       newSecret: \Infocyph\OTP\HOTP::generateSecret(),
       label: 'alice@example.com',
       issuer: 'Example App',
       initialCounter: 0,
       gracePeriodInSeconds: 300,
   );

Do not share counter or replay identity between generations. Provision and
persist the same ``initialCounter`` for the replacement.

OCRA rotation
-------------

.. code-block:: php

   $rotation = $ocra->planRotation(
       newSecret: \Infocyph\OTP\OCRA::generateSecret(32),
       label: 'alice@example.com',
       issuer: 'Example App',
       gracePeriodInSeconds: 300,
   );

The new object uses the same parsed suite with the replacement Base32 secret.
If the suite itself changes, create a separately versioned enrollment rather
than treating it as only a secret rotation.

Validation
----------

Replacement secrets are normalized canonical Base32, must decode to at least 16
bytes, must differ from the current secret, and must be valid for a fresh
protocol object. Negative grace and timestamps that overflow the supported
range are rejected.

The ``SecretRotation`` value object also verifies that optional enrollment
material contains the exact replacement secret.

Compromise response
-------------------

For suspected disclosure:

* choose immediate cutover where possible;
* invalidate active sessions according to application policy;
* rotate factor IDs and replay state;
* notify the account owner;
* audit without recording secrets or enrollment payloads; and
* review recovery codes and other factors independently.

Rotating an OTP factor does not rotate Generic OTP or recovery-code HMAC keys.
Those keys have separate operational rotation procedures because changing them
invalidates centrally stored digests.
