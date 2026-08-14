OCRA
====

OCRA implements RFC 6287 challenge-response. It is suited to explicit
transaction challenges, counter-bound responses, PIN-derived inputs, session
binding, time-bound responses, mutual challenge composition, and signature
challenge composition.

OCRA requires both parties to agree on the exact suite and input encoding. It is
not a general authenticator-app replacement.

Key construction
----------------

Use the constructor for a raw binary shared key:

.. code-block:: php

   use Infocyph\OTP\OCRA;

   $ocra = new OCRA(
       suite: 'OCRA-1:HOTP-SHA256-8:QN08',
       sharedKey: $rawSharedKey,
   );

Use ``fromBase32()`` for an enrolled Base32 secret:

.. code-block:: php

   $secret = OCRA::generateSecret(32);
   $ocra = OCRA::fromBase32(
       'OCRA-1:HOTP-SHA256-8:QN08',
       $secret,
   );

Raw and decoded Base32 keys must contain 16–1024 bytes. ``generateSecret()``
returns canonical unpadded uppercase Base32 and uses 20 random bytes by default.

Suite grammar
-------------

The accepted form is:

.. code-block:: text

   OCRA-1:HOTP-SHA{1|256|512}-{0|4..9}:[C-]Q{N|A|H}{04..64}[-P{SHA1|SHA256|SHA512}][-S{001..512}][-T{step}]

Components mean:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Component
     - Meaning
   * - ``SHA1``, ``SHA256``, ``SHA512``
     - HMAC algorithm
   * - ``0``
     - Return the complete HMAC as uppercase hexadecimal
   * - ``4..9``
     - Return a dynamically truncated decimal response
   * - ``C``
     - Require a non-negative counter
   * - ``QN04..QN64``
     - Decimal challenge with 1 through the declared maximum digits
   * - ``QA04..QA64``
     - ASCII alphanumeric challenge with 1 through the declared maximum bytes
   * - ``QH04..QH64``
     - Hexadecimal challenge with 1 through the declared maximum nibbles
   * - ``P...``
     - Require a PIN hashed with the named algorithm before OCRA calculation
   * - ``S001..S512``
     - Require non-empty UTF-8 session data within the declared byte length
   * - ``T...``
     - Require a timestamp with a 1–59 second/minute or 1–48 hour step

``OcraSuite::parse()`` is authoritative and is available through
``$ocra->getSuite()``:

.. code-block:: php

   $suite = $ocra->getSuite();

   $suite->suite;
   $suite->algorithm;
   $suite->digits;
   $suite->counterEnabled;
   $suite->challengeFormat;
   $suite->challengeLength;
   $suite->pinAlgorithm;
   $suite->sessionLength;
   $suite->timeStepSeconds;
   $suite->usesPin();
   $suite->usesSession();
   $suite->usesTime();

Challenge-only operation
------------------------

.. code-block:: php

   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08', $rawSharedKey);

   $response = $ocra->generate(challenge: '12345678');
   $valid = $ocra->verify(
       otp: $response,
       challenge: '12345678',
   );

Supplying counter, PIN, session, or timestamp to this suite throws because those
values are not authenticated by the suite.

Counter operation
-----------------

.. code-block:: php

   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', $rawSharedKey);

   $response = $ocra->generate('12345678', counter: 4);
   $result = $ocra->verifyWithResult(
       $response,
       '12345678',
       counter: 4,
       cache: $stateCache,
       factorId: 'user-42:ocra-counter:secret-v1',
   );

   if ($result->matched) {
       $result->matchedCounter; // 4
       $result->nextCounter;    // 5
   }

A counter is required exactly when the suite contains ``C``. Replay protection
uses monotonic ``advance()``; an equal or lower accepted counter is rejected.
Persist ``nextCounter`` in application state after success.

PIN operation
-------------

.. code-block:: php

   $ocra = new OCRA(
       'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
       $rawSharedKey,
   );

   $response = $ocra->generate('12345678', pin: $userPin);
   $valid = $ocra->verify($response, '12345678', pin: $submittedPin);

The PIN must be non-empty and at most 1024 bytes. The suite hashes it with
SHA-1, SHA-256, or SHA-512 as declared. OCRA PIN support does not provide PIN
enrollment, password hashing for persistence, throttling, lockout, or UI policy.
Do not store a recoverable PIN merely because it is an OCRA input.

Session operation
-----------------

.. code-block:: php

   $ocra = new OCRA(
       'OCRA-1:HOTP-SHA256-8:QN08-S064',
       $rawSharedKey,
   );

   $response = $ocra->generate(
       '12345678',
       session: 'checkout-session-7',
   );

Session input is non-empty valid UTF-8 and its encoded byte length may not exceed
the suite length. It is left-padded with NUL bytes to that length for the OCRA
message.

When an external protocol represents valid UTF-8 session data as hexadecimal,
decode it by name:

.. code-block:: php

   $sessionBytes = OCRA::sessionHex('414243'); // "ABC"
   $response = $ocra->generate('12345678', session: $sessionBytes);

``sessionHex()`` rejects empty or non-hexadecimal text and decoded bytes that are
not valid UTF-8. Odd nibbles receive a leading zero nibble before decoding.

Time operation
--------------

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $ocra = new OCRA(
       'OCRA-1:HOTP-SHA256-8:QN08-T1M',
       $rawSharedKey,
   );

   $response = $ocra->generate(
       '12345678',
       timestamp: time(),
   );

   $result = $ocra->verifyWithResult(
       otp: $submittedResponse,
       challenge: '12345678',
       timestamp: time(),
       timeWindow: new VerificationWindow(past: 1, future: 1),
       cache: $stateCache,
       factorId: 'user-42:ocra-time:secret-v1',
       replayTtl: 180,
   );

Timestamp is required exactly for a ``T`` suite and must be non-negative. A
non-zero verification window is invalid for a suite without time. If replay TTL
is supplied for a time suite, it must cover:

.. code-block:: text

   timeStepSeconds * (past + future + 1)

A time match reports ``driftOffset`` in steps, not seconds.

Combined inputs
---------------

A suite can require several inputs:

.. code-block:: php

   $ocra = new OCRA(
       'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1-S064-T1M',
       $rawSharedKey,
   );

   $response = $ocra->generate(
       challenge: '12345678',
       counter: 7,
       pin: '1234',
       session: 'checkout-session-7',
       timestamp: time(),
   );

Every required value must be present in generation and verification. Passing an
extra value for a component absent from the suite throws
``InvalidArgumentException``.

Mutual challenge
----------------

Use the explicit mutual methods so client/server challenge composition is not
hidden:

.. code-block:: php

   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', $rawSharedKey);

   $response = $ocra->generateMutual(
       clientChallenge: 'CLI22220',
       serverChallenge: 'SRV11110',
   );

   $valid = $ocra->verifyMutual(
       otp: $response,
       clientChallenge: 'CLI22220',
       serverChallenge: 'SRV11110',
   );

Each component must independently match the suite challenge shape. The combined
challenge may not exceed 128 bytes. ``verifyMutual()`` returns a boolean and has no
CacheLayer replay arguments. Issue unpredictable server challenges and atomically
consume them in application storage.

Signature challenge
-------------------

``generateSignature()`` names a signature-composition operation while using the
same suite-defined calculation:

.. code-block:: php

   $signature = $ocra->generateSignature('SIG10000');
   $valid = $ocra->verify($signature, 'SIG10000');

Define a canonical, unambiguous representation of transaction data before
creating the signature challenge. Do not concatenate variable fields without
lengths or a documented encoding.

Replay behavior
---------------

``verifyWithResult()`` supports replay state through CacheLayer:

* counter suites store the greatest accepted counter without a TTL;
* non-counter suites consume a token with a required application TTL;
* the token identity covers the complete authenticated OCRA message; and
* a matched response rejected by storage returns reason ``Replay`` with
  ``matched === false``.

A replay TTL is mandatory for non-counter messages. Select a bounded retention
period that covers the entire business validity and time window. Do not make it
shorter than the server challenge validity. Counter suites reject a TTL because
their monotonic state must remain durable for the factor generation.

Output handling
---------------

Truncated suites accept only decimal output of the exact configured width.
Full-HMAC suites accept hexadecimal input of the algorithm's exact width and
normalize it to uppercase for comparison:

* SHA-1: 40 hexadecimal characters;
* SHA-256: 64 hexadecimal characters;
* SHA-512: 128 hexadecimal characters.

Wrong shape returns ``Malformed``. Correct shape with no match returns
``Mismatch``. Missing or irrelevant suite inputs throw before credential shape is
evaluated.

Challenge encoding
------------------

Numeric challenges are converted as arbitrary-size decimal integers; they are
not limited by PHP integer width. Alphanumeric challenges are used as bytes.
Hexadecimal challenges decode as bytes, with a leading zero nibble added for odd
lengths. Encoded challenge data is padded to the RFC message field width.

Provisioning
------------

.. code-block:: php

   $payload = $ocra->getEnrollmentPayload(
       'alice@example.com',
       'Example App',
       withQrSvg: true,
   );

The URI contains ``algorithm``, ``digits``, and ``ocraSuite`` that agree with the
parsed suite. ``otpauth://ocra`` is a library/client convention, not a provisioning
format standardized by RFC 6287. Confirm explicit client support.
