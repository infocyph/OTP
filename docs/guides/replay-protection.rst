Replay Protection
=================

Overview
--------

Replay protection is intentionally pluggable.

Available contract:

- ``Infocyph\OTP\Contracts\ReplayStoreInterface``

Included store:

- ``Infocyph\OTP\Stores\InMemoryReplayStore``

Recommended policy
------------------

TOTP
~~~~

- Store the last accepted timestep per user or device binding.
- Reject the same timestep once accepted.

HOTP
~~~~

- Store the last accepted counter.
- Reject already-used counters.
- Persist any resynchronized counter once accepted.

OCRA
~~~~

- Reject reused challenge/counter combinations where the flow requires single use.

Example
-------

.. code-block:: php

   <?php
   use Infocyph\OTP\Stores\InMemoryReplayStore;
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $store = new InMemoryReplayStore();

   $result = $totp->verifyWithWindow(
       $otp,
       window: new VerificationWindow(past: 1, future: 1),
       replayStore: $store,
       binding: 'user-42',
   );

Persistent implementations
--------------------------

The in-memory replay store is mainly for tests and lightweight scenarios.

See :doc:`custom-stores` for a database-oriented example implementing ``ReplayStoreInterface``.
