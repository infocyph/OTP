Quick Start
===========

TOTP
----

.. code-block:: php

   <?php
   use Infocyph\OTP\TOTP;

   $secret = TOTP::generateSecret();

   $totp = (new TOTP($secret))
       ->setAlgorithm('sha256');

   $otp = $totp->getOTP();
   $isValid = $totp->verify($otp);

Advanced TOTP verification:

.. code-block:: php

   <?php
   use Infocyph\OTP\Stores\InMemoryReplayStore;
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $totp->verifyWithWindow(
       $otp,
       timestamp: time(),
       window: new VerificationWindow(past: 1, future: 1),
       replayStore: new InMemoryReplayStore(),
       binding: 'user-42',
   );

   $result->matched;
   $result->matchedTimestep;
   $result->driftOffset;
   $result->replayDetected;

HOTP
----

.. code-block:: php

   <?php
   use Infocyph\OTP\HOTP;

   $secret = HOTP::generateSecret();
   $hotp = (new HOTP($secret))
       ->setCounter(3)
       ->setAlgorithm('sha256');

   $otp = $hotp->getOTP(346);
   $isValid = $hotp->verify($otp, 346);

Generic OTP
-----------

.. code-block:: php

   <?php
   use Infocyph\OTP\OTP;
   use Psr\Cache\CacheItemPoolInterface;

   /** @var CacheItemPoolInterface $cachePool */
   $otp = new OTP(
       digitCount: 6,
       validUpto: 60,
       retry: 3,
       hashAlgorithm: 'xxh128',
       cacheAdapter: $cachePool,
   );

   $code = $otp->generate('signup:alice@example.com');
   $otp->verify('signup:alice@example.com', $code);

Recovery codes
--------------

.. code-block:: php

   <?php
   use Infocyph\OTP\RecoveryCodes;
   use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

   $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());
   $generated = $codes->generate('user-42');
   $consumed = $codes->consume('user-42', $generated->plainCodes[0]);
