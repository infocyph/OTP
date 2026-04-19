HOTP Guide
==========

Basic usage
-----------

.. code-block:: php

   use Infocyph\OTP\HOTP;

   $hotp = (new HOTP($secret))
       ->setCounter(3)
       ->setAlgorithm('sha1');

   $otp = $hotp->getOTP(10);
   $hotp->verify($otp, 10);

Look-ahead verification
-----------------------

HOTP often needs controlled counter resynchronization.

.. code-block:: php

   $hotp->verify($otp, counter: 10, lookAhead: 5);

Rich verification result
------------------------

.. code-block:: php

   use Infocyph\OTP\Stores\InMemoryReplayStore;

   $result = $hotp->verifyWithResult(
       $otp,
       counter: 10,
       lookAhead: 5,
       replayStore: new InMemoryReplayStore(),
       binding: 'device-1',
   );

   $result->matched;
   $result->matchedCounter;
   $result->driftOffset;
   $result->replayDetected;
