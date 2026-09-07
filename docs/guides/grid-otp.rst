GridOTP
=======

``GridOTP`` is Infocyph's dynamic-grid challenge-response primitive. It is a
library-defined knowledge-factor protocol, not an RFC algorithm and not an
``otpauth://`` format.

The enrolled secret uses the 32-symbol alphabet:

.. code-block:: text

   ABCDEFGHJKLMNPQRSTUVWXYZ23456789

Generate a random secret rather than deriving one from personal information:

.. code-block:: php

   use Infocyph\OTP\GridOTP;

   $secret = GridOTP::generateSecret();
   $gridOtp = new GridOTP($stateCache, $secret);
   $challenge = $gridOtp->issue('user-42:grid:v1');
   $response = GridOTP::respond($challenge, $secret);
   $result = $gridOtp->verifyWithResult('user-42:grid:v1', $challenge, $response);

Each challenge contains a fresh 128-bit ID, a complete dynamic mapping from the
32 secret symbols to decimal labels, 6..10 distinct one-based secret positions,
and issuance/expiration timestamps. Response labels are balanced so each digit
appears three or four times across the grid.

The cached state stores a SHA-256 digest of the canonical challenge, remaining
attempts, absolute expiration, and consumed status. Altering the grid, positions,
secret length, or timestamps invalidates the challenge.

Malformed responses do not consume an attempt. A wrong well-formed response
decrements attempts without extending expiration. Success leaves a consumed
marker until the original expiration so subsequent valid requests are reported
as replay.

GridOTP intentionally requires a coordinated CacheLayer lock because attempts,
expiry, challenge-integrity state, and consumption form one multi-field state
machine.

A captured response cannot be reused against a new challenge, and the user never
types the underlying secret directly. This improves resistance to simple
keyloggers. It is not shoulder-surfing proof: repeated observations of the full
grid, positions, and response can intersect candidate sets and eventually
recover secret symbols. Treat GridOTP as one knowledge factor, not MFA.
