Recovery codes
==============

Recovery codes provide a one-time fallback when the primary factor is
unavailable. The package generates plaintext codes, stores only
binding-specific HMAC digests through an atomic contract, and returns committed
batch metadata.

Construction
------------

.. code-block:: php

   use Infocyph\OTP\RecoveryCodes;
   use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

   $codes = new RecoveryCodes(
       store: new InMemoryRecoveryCodeStore(), // tests/local development only
       key: $recoveryCodeHmacKey,
   );

The raw HMAC key must contain 16–1024 bytes and must be distinct from Generic
OTP, encryption, session, and factor keys.

Generate a default batch
------------------------

.. code-block:: php

   $batch = $codes->generate(binding: 'user-42');

   $batch->plainCodes;      // ten one-time plaintext values
   $batch->totalGenerated;  // 10
   $batch->remainingCount;  // 10
   $batch->lastUsedAt;      // null for the new batch

Default codes contain 12 unformatted characters displayed as
``XXXX-XXXX-XXXX``. The alphabet excludes visually ambiguous characters and
provides approximately 60 bits of entropy per code.

Display ``plainCodes`` exactly once through an authenticated, non-cacheable
response. Encourage offline secure storage. The plaintext cannot be recovered
from the store.

Consume
-------

.. code-block:: php

   $result = $codes->consume(
       binding: 'user-42',
       code: $submittedCode,
   );

   if ($result->consumed) {
       $result->remainingCount;
       $result->totalGenerated;
       $result->lastUsedAt;
   }

Input is trimmed, uppercased, and ignores spaces and hyphens. It must normalize
to 6–128 ASCII letters/digits. Raw input over 512 bytes is rejected before
normalization.

The store's atomic mutation returns whether consumption occurred and the
committed total, remaining, and last-used values. The service does not perform a
fallible metadata read after a successful mutation.

Single-use and concurrency
--------------------------

Two concurrent attempts with one valid code must produce one success. The
successful transaction removes the digest and records ``lastUsedAt``; the losing
transaction observes the committed remaining count. A custom store must not
implement consume as an unlocked read followed by delete.

Regenerate
----------

.. code-block:: php

   $replacement = $codes->generate('user-42');

Generation atomically replaces the complete active batch. Every old unused code
becomes invalid immediately. Use this after suspected disclosure, successful
account recovery, or an explicit user request. Do not append a new batch to the
old one.

Custom format
-------------

.. code-block:: php

   $batch = $codes->generate(
       binding: 'user-42',
       count: 12,
       length: 16,
       groupSize: 4,
       characterSet: 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
   );

Bounds:

* count: 1–100;
* unformatted length: 6–128 characters;
* group size: 0 through the code length, where 0 disables separators;
* alphabet: ASCII letters and digits with at least two unique values; and
* entropy: at least 40 bits after case normalization and deduplication.

Duplicate alphabet characters are removed. The generator also verifies that
the alphabet/length space can safely produce the requested number of unique
codes.

Binding
-------

Bindings contain 1–190 bytes and should identify the account or recovery
credential generation. The digest includes both the binding and normalized
code:

.. code-block:: text

   HMAC-SHA-256(key, "recovery-code" || NUL || binding || NUL || normalizedCode)

The same plaintext therefore has different digests for different bindings.

Application policy
------------------

The package does not decide:

* whether recovery bypasses all other factors;
* when identity proof is sufficient;
* how many codes users must retain;
* whether a successful recovery forces password/factor rotation;
* which notifications and audit events are required; or
* when low remaining counts trigger regeneration.

Rate-limit all recovery attempts, use generic outward failures, notify the
account owner after use, and consider invalidating all sessions or initiating a
factor review after high-risk recovery.
