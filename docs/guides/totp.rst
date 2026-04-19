TOTP Guide
==========

Creating a TOTP instance
------------------------

.. code-block:: php

   use Infocyph\OTP\TOTP;

   $totp = new TOTP($secret, digitCount: 6, period: 30);

Windowed verification
---------------------

Use ``verify()`` when a boolean is enough:

.. code-block:: php

   $totp->verify($otp, timestamp: time(), pastWindows: 1, futureWindows: 1);

Use ``verifyWithWindow()`` when you need more detail:

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $totp->verifyWithWindow(
       $otp,
       timestamp: time(),
       window: new VerificationWindow(past: 1, future: 0),
   );

   $result->matched;
   $result->matchedTimestep;
   $result->driftOffset;
   $result->isExact();
   $result->isDrifted();

Time helpers
------------

.. code-block:: php

   $totp->getCurrentTimeStep();
   $totp->getRemainingSeconds();
   $totp->getTimeStepFromTimestamp(1716532624);

Replay protection
-----------------

.. code-block:: php

   use Infocyph\OTP\Stores\InMemoryReplayStore;
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $store = new InMemoryReplayStore();

   $result = $totp->verifyWithWindow(
       $otp,
       window: new VerificationWindow(past: 1, future: 1),
       replayStore: $store,
       binding: 'user-42',
   );

Rotation helper
---------------

.. code-block:: php

   $rotation = $totp->rotateSecret($newSecret, gracePeriodInSeconds: 3600);

   $rotation['current'];
   $rotation['next'];
   $rotation['overlapUntil'];
