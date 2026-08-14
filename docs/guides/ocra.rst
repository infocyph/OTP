OCRA
====

``OcraSuite::parse()`` is the authoritative suite representation. Suite and key
are immutable; counter, PIN, session, timestamp, and challenge are per-operation
inputs. Missing required or irrelevant supplied inputs throw
``InvalidArgumentException``.

.. code-block:: php

   $ocra = new \Infocyph\OTP\OCRA(
       'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
       $rawKey,
   );
   $code = $ocra->generate('12345678', counter: 4, pin: '1234');

Use ``generateMutual(clientChallenge, serverChallenge, ...)`` for mutual mode
and ``generateSignature()`` for explicit signature composition. Session input
is actual UTF-8 data; ``OCRA::sessionHex()`` decodes a named hexadecimal
integration input. Time suites require a timestamp and can verify an explicit
``VerificationWindow``.

Odd hexadecimal nibbles are prefixed with zero before byte decoding. Full-HMAC
``t=0`` output is uppercase hexadecimal; truncated output is 4..9 digits.
Counter suites use monotonic state. Non-counter suites consume a SHA-256 digest
of the complete authenticated message. Optional challenge replay TTLs should be
chosen for operational retention and must cover the complete time acceptance
window.

``otpauth://ocra`` is a client convention, not RFC-standardized provisioning.
