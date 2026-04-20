Step-Up Authentication Helpers
==============================

Overview
--------

The package includes small step-up policy helpers in ``Infocyph\OTP\Support\StepUp``.

These helpers answer questions like:

- was an OTP verified recently enough?
- should the user be asked for a fresh OTP now?
- how old is the last successful verification?

Quick example
-------------

.. code-block:: php

   <?php
   use Infocyph\OTP\Support\StepUp;

   $requiresFreshOtp = StepUp::requiresFreshOtp($verifiedAt, 300);

Assessing freshness in detail
-----------------------------

.. code-block:: php

   <?php
   $assessment = StepUp::assess($verifiedAt, 300);

   $assessment->requiresFreshOtp;
   $assessment->verifiedAt;
   $assessment->ageInSeconds;
   $assessment->freshForSeconds;
   $assessment->expiresAt;
   $assessment->isFresh();

Checking a custom reference time
--------------------------------

.. code-block:: php

   <?php
   $assessment = StepUp::assess(
       verifiedAt: $verifiedAt,
       seconds: 300,
       now: new DateTimeImmutable('2026-04-20 10:04:00'),
   );

Recommended usage
-----------------

- use these helpers for high-risk actions such as password change or payout approval
- store the ``verifiedAt`` from your OTP verification result or session state
- keep the freshness window short for sensitive flows

What this helper does not do
----------------------------

- it does not manage sessions
- it does not prompt the user
- it does not know which MFA factor was used

Those parts stay in your application layer.
