Recovery Codes
==============

Generating codes
----------------

.. code-block:: php

   use Infocyph\OTP\RecoveryCodes;
   use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

   $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());

   $generated = $codes->generate(
       binding: 'user-42',
       count: 10,
       length: 10,
       groupSize: 4,
   );

   $generated->plainCodes;
   $generated->totalGenerated;
   $generated->remainingCount;

Consuming a code
----------------

.. code-block:: php

   $result = $codes->consume('user-42', $generated->plainCodes[0]);

   $result->consumed;
   $result->reason;
   $result->remainingCount;
   $result->lastUsedAt;

Behavior
--------

- Codes are displayed in a user-friendly grouped format.
- Stored values are hashed before persistence.
- Generating a new set replaces the old set.
- A consumed code cannot be reused.
