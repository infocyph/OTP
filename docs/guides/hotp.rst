HOTP
====

.. code-block:: php

   $hotp = new \Infocyph\OTP\HOTP($secret, digits: 6, algorithm: 'sha1');
   $code = $hotp->generate(10);
   $result = $hotp->verifyWithResult($code, 10, replayStore: $store, factorId: $factorId);

``matchedCounter`` is the counter that generated the accepted code.
``nextCounter`` is the value the server must durably persist. Look-ahead is
bounded to 100 and replay state advances only when the submitted counter is
greater than stored state. Enrollment receives ``initialCounter`` explicitly
and always emits it in the URI.
