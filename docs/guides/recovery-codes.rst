Recovery Codes
==============

Generating codes
----------------

.. code-block:: php

   <?php
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

For production, provide a purpose-specific HMAC key kept outside the recovery-code store:

.. code-block:: php

   <?php
   $codes = new RecoveryCodes(
       $store,
       hashAlgorithm: 'sha256',
       hashKey: $applicationRecoveryCodeKey,
   );

The HMAC key must contain at least 16 bytes. Without a key, the package stores a SHA-256 or SHA-512 digest.

Consuming a code
----------------

.. code-block:: php

   <?php
   $result = $codes->consume('user-42', $generated->plainCodes[0]);

   $result->consumed;
   $result->reason;
   $result->remainingCount;
   $result->lastUsedAt;

Behavior
--------

- Codes are displayed in a user-friendly grouped format.
- Stored values are hashed before persistence.
- Hash algorithms are restricted to SHA-256 and SHA-512.
- Generating a new set replaces the old set.
- A consumed code cannot be reused.
- Counts, lengths, grouping, and character sets are bounded and validated before generation.

Persistent tracking
-------------------

The included in-memory store is useful for tests and simple examples, but production systems should use a persistent store.

See :doc:`custom-stores` for:

- a database schema example
- a PDO-backed ``RecoveryCodeStoreInterface`` implementation
- guidance on tracking total issued, remaining, and last-used values over time
