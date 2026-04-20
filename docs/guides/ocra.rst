OCRA Guide
==========

RFC context
-----------

OCRA is defined in RFC6287. It extends the HOTP family into richer challenge-response flows.

Compared with HOTP and TOTP, OCRA can include:

- a challenge
- an optional counter
- an optional PIN-derived input
- an optional session value
- an optional time input

This makes OCRA suitable for transaction signing and higher-assurance challenge-response scenarios, not just login OTPs.

Understanding the suite string
------------------------------

An OCRA flow is defined by its suite string.

Example:

.. code-block:: text

   OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1

This means:

- ``OCRA-1``: protocol version
- ``HOTP-SHA256``: HMAC family and hash algorithm
- ``8``: output digits
- ``C``: counter is required
- ``QN08``: numeric challenge of length 8
- ``PSHA1``: PIN input is hashed with SHA1

Common suite patterns
---------------------

You will usually encounter OCRA suites in a few recurring categories:

- challenge only
- challenge plus counter
- challenge plus PIN
- challenge plus session
- challenge plus time
- combinations of the above

Examples:

.. code-block:: text

   OCRA-1:HOTP-SHA1-6:QN08
   OCRA-1:HOTP-SHA512-8:C-QN08
   OCRA-1:HOTP-SHA256-8:QN08-PSHA1
   OCRA-1:HOTP-SHA256-8:QN08-S064
   OCRA-1:HOTP-SHA512-8:QN08-T1M
   OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1

Generating a shared secret
--------------------------

OCRA uses a shared secret between client and server, just like the other OTP families.

You can generate one with:

.. code-block:: php

   <?php
   use Infocyph\OTP\OCRA;

   $sharedKey = OCRA::generateSecret();

If your integration needs a specific keying strategy, you can also supply an application-managed shared key when constructing the instance.

Creating an OCRA instance
-------------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\OCRA;

   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', $sharedKey);
   $ocra->setPin('1234');

   $code = $ocra->generate('12345678', 0);
   $ocra->verify($code, '12345678', 0);

Detailed generation examples
----------------------------

Numeric challenge only
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', $sharedKey);
   $code = $ocra->generate('12345678');

Counter plus challenge plus PIN:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', $sharedKey);
   $ocra->setPin('1234');

   $challenge = '12345678';
   $counter = 5;

   $code = $ocra->generate($challenge, $counter);

Challenge-only flow:
~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', $sharedKey);
   $code = $ocra->generate('00000000');

Counter without PIN:
~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA512-8:C-QN08', $sharedKey);
   $code = $ocra->generate('12345678', 10);

PIN without counter:
~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', $sharedKey);
   $ocra->setPin('1234');
   $code = $ocra->generate('12345678');

Session-based flow:
~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', $sharedKey);
   $ocra->setSession('A1B2C3D4');
   $code = $ocra->generate('12345678');

Time-based flow:
~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA512-8:QN08-T1M', $sharedKey);
   $ocra->setTime(new DateTimeImmutable('2026-04-19 12:00:00 UTC'));
   $code = $ocra->generate('12345678');

Alphanumeric challenge flow:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', $sharedKey);
   $code = $ocra->generate('CLI22220SRV11110');

Hexadecimal challenge flow:
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QH08', $sharedKey);
   $code = $ocra->generate('A1B2C3D4');

Verification examples
---------------------

Basic verification:

.. code-block:: php

   <?php
   $isValid = $ocra->verify($code, '12345678', 0);

Challenge-only verification:

.. code-block:: php

   <?php
   $challengeOnly = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', $sharedKey);
   $otp = $challengeOnly->generate('00000000');
   $isValid = $challengeOnly->verify($otp, '00000000');

Rich verification result:

.. code-block:: php

   <?php
   $result = $ocra->verifyWithResult($code, '12345678', 0);

   $result->matched;
   $result->matchedCounter;
   $result->replayDetected;

Verification with replay tracking:

.. code-block:: php

   <?php
   use Infocyph\OTP\Stores\InMemoryReplayStore;

   $store = new InMemoryReplayStore();
   $result = $ocra->verifyWithResult(
       $code,
       '12345678',
       0,
       $store,
       'user-42',
   );

Optional suite inputs
---------------------

Depending on the suite, you may need:

- ``setPin()``
- ``setSession()``
- ``setTime()``

Example with a session value:

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', $sharedKey);
   $ocra->setSession('A1B2C3D4');
   $code = $ocra->generate('12345678');

Example with both counter and PIN:

.. code-block:: php

   <?php
   $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', $sharedKey);
   $ocra->setPin('1234');
   $code = $ocra->generate('12345678', 7);

Notes on optional inputs:

- if the suite includes ``C``, you should provide a counter
- if the suite includes ``PSHA1`` / ``PSHA256`` / ``PSHA512``, you should call ``setPin()``
- if the suite includes ``Snnn``, you should call ``setSession()``
- if the suite includes ``T...``, you can optionally call ``setTime()`` to verify or generate for a specific moment

Parsed suite details
--------------------

.. code-block:: php

   <?php
   $suite = $ocra->getSuite();

   $suite->algorithm;
   $suite->digits;
   $suite->counterEnabled;
   $suite->challengeFormat;
   $suite->challengeLength;
   $suite->optionals;

Challenge formats
-----------------

The library supports the major RFC challenge styles:

- ``QNxx``: numeric challenge
- ``QAxx``: alphanumeric challenge
- ``QHxx``: hexadecimal challenge

Examples:

.. code-block:: php

   <?php
   (new OCRA('OCRA-1:HOTP-SHA1-6:QN08', $sharedKey))->generate('12345678');
   (new OCRA('OCRA-1:HOTP-SHA256-8:QA08', $sharedKey))->generate('CLI22220SRV11110');
   (new OCRA('OCRA-1:HOTP-SHA256-8:QH08', $sharedKey))->generate('A1B2C3D4');

In practice:

- ``QNxx`` is useful for numeric server-issued challenges
- ``QAxx`` is useful for mixed transaction strings or structured references
- ``QHxx`` is useful when challenge material is already represented in hexadecimal form

Replay protection
-----------------

RFC6287 defines the derivation rules, but replay prevention is still a server-side policy concern.

For many OCRA use cases, you should reject:

- reused challenge values
- reused counter values where counters are present
- previously accepted challenge and counter combinations

Example:

.. code-block:: php

   <?php
   use Infocyph\OTP\Stores\InMemoryReplayStore;

   $result = $ocra->verifyWithResult(
       $code,
       challenge: '12345678',
       counter: 0,
       replayStore: new InMemoryReplayStore(),
       binding: 'user-42',
   );

When to choose OCRA
-------------------

Choose OCRA when you need more than a simple login OTP, for example:

- transaction confirmation
- challenge-response MFA
- flows combining PIN, counter, and challenge data

If you only need rotating time-based login codes, TOTP is usually simpler.

Provisioning and QR examples
----------------------------

If your OCRA client workflow supports provisioning via ``otpauth://``, you can generate both the URI and an SVG QR:

.. code-block:: php

   <?php
   $uri = $ocra->getProvisioningUri('alice@example.com', 'Example App');
   $svg = $ocra->getProvisioningUriQR('alice@example.com', 'Example App');

See :doc:`provisioning` for the general provisioning flow.
