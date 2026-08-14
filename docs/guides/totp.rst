TOTP
====

TOTP configuration is immutable. Verification checks current, past one, future
one, then expands by distance. Total drift is bounded to 100 steps.

.. code-block:: php

   $result = $totp->verifyWithWindow(
       $submitted,
       window: new \Infocyph\OTP\ValueObjects\VerificationWindow(1, 1),
       replayStore: $atomicStore,
       factorId: $factorId,
   );

Supplying a replay store always enables monotonic protection. Atomic ``advance``
accepts only a timestep greater than the last accepted one, so an older unused
window cannot be accepted after a newer step. ``getRemainingSeconds()`` returns
the full period at the instant a new step begins.
