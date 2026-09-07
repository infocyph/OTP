GridOTP
=======

``GridOTP`` is Infocyph's dynamic-grid challenge-response primitive. It is a
library-defined knowledge-factor protocol, not an RFC algorithm and not an
``otpauth://`` format.

The enrolled secret uses the 32-symbol alphabet:

.. code-block:: text

   ABCDEFGHJKLMNPQRSTUVWXYZ23456789

Each challenge contains a fresh 128-bit ID, a complete dynamic mapping from the
32 secret symbols to decimal labels, 6..10 distinct one-based secret positions,
and issuance/expiration timestamps. Response labels are balanced so each digit
appears three or four times across the grid.

Enrollment
----------

Generate the secret with the library rather than deriving it from personal
information. The verifier must persist the same secret encrypted because it is
needed to verify responses. The user/client must receive its copy through an
authenticated, confidential enrollment channel.

.. code-block:: php

   use Infocyph\OTP\GridOTP;

   $secret = GridOTP::generateSecret(); // 12 symbols by default
   $factorId = 'user-42:grid:secret-v1';

   persistGridFactor(
       factorId: $factorId,
       encryptedSecret: encryptFactorSecret($secret),
   );

   // Deliver $secret once to the user's trusted client/card and do not log it.

A secret can contain 8..32 symbols. The default 12-symbol secret is the
recommended general-purpose profile. Rotating the secret must create a new
factor generation and factor ID.

Complete authentication flow
----------------------------

``$stateCache`` below is the shared authentication-state CacheLayer described in
:doc:`storage`. GridOTP always requires the coordinated lock because attempts,
expiry, integrity, and consumption are one multi-field state transition.

The verifier loads the enrolled secret and issues a challenge:

.. code-block:: php

   use Infocyph\OTP\GridOTP;

   $factor = loadGridFactor('user-42:grid:secret-v1');
   $serverSecret = decryptFactorSecret($factor->encryptedSecret);

   $gridOtp = new GridOTP(
       cache: $stateCache,
       secret: $serverSecret,
       challengeSize: 6,
       ttlSeconds: 120,
       maxAttempts: 3,
   );

   $challenge = $gridOtp->issue($factor->factorId);
   $challengeJson = json_encode(
       $challenge->toArray(),
       JSON_THROW_ON_ERROR,
   );

Send the challenge to the client. A human client renders the complete ``grid``
mapping and asks for the digits corresponding to the requested ``positions`` in
the user's enrolled secret. For a programmable client, the same operation is
available through ``respond()``:

.. code-block:: php

   use Infocyph\OTP\GridOTP;
   use Infocyph\OTP\ValueObjects\GridChallenge;

   $challenge = GridChallenge::fromArray(
       json_decode($challengeJson, true, 512, JSON_THROW_ON_ERROR),
   );

   // This runs on the client/user side where the enrolled secret is available.
   $response = GridOTP::respond(
       challenge: $challenge,
       secret: $clientSecret,
   );

   // Send both $challenge->toArray() and $response back to the verifier.

For example, if the requested positions are ``[2, 7, 1, 10, 4, 9]``, the client
reads those one-based positions from the enrolled secret, looks up each secret
symbol in the current challenge grid, and submits the resulting six decimal
digits in the same order. The underlying secret itself is never typed or sent in
the authentication response.

The verifier reconstructs the returned challenge and verifies the response:

.. code-block:: php

   use Infocyph\OTP\ValueObjects\GridChallenge;
   use Infocyph\OTP\VerificationReason;

   $submittedChallenge = GridChallenge::fromArray(
       json_decode($submittedChallengeJson, true, 512, JSON_THROW_ON_ERROR),
   );

   $result = $gridOtp->verifyWithResult(
       factorId: $factor->factorId,
       challenge: $submittedChallenge,
       response: $submittedResponse,
   );

   if ($result->matched) {
       // Complete the application's authenticated session transition.
   } elseif ($result->reason === VerificationReason::Replay) {
       // This challenge was already consumed. Fail closed.
   } else {
       // Wrong, expired, malformed, or tampered challenge/response.
   }

Returning the challenge from the client does not make it trusted. The server-side
state stores a SHA-256 digest of the canonical challenge. Altering the grid,
positions, secret length, issuance time, or expiration causes verification to
fail before a response can be accepted.

Attempts, expiry, and replay
----------------------------

Malformed responses do not consume an attempt. A wrong well-formed response
decrements attempts without extending expiration. Once the last allowed attempt
is consumed, the state is deleted and the challenge cannot be reused.

Success leaves a consumed marker until the original expiration so subsequent
valid requests are reported as replay. The entire mutation runs under the
configured CacheLayer coordinated lock; GridOTP intentionally does not split the
attempt counter and replay marker into separate atomic operations.

Security position
-----------------

A captured response cannot be reused against a new challenge, and the user never
types the underlying secret directly. This improves resistance to simple
keyloggers and avoids transmitting the enrolled secret during normal login.

It is not shoulder-surfing proof. An observer who repeatedly captures the full
grid, requested positions, and submitted responses can intersect candidate sets
and eventually recover secret symbols. Treat GridOTP as one knowledge factor,
not MFA. Prefer standards-based Passkey/WebAuthn when phishing-resistant public-
key authentication is available and appropriate.

Operational rules
-----------------

* Encrypt the verifier copy of the secret at rest.
* Keep the user's/client's secret out of logs, analytics, screenshots, and
  recovery emails.
* Use a generation-specific factor ID and rotate it with the secret.
* Keep challenge TTL and attempt count small.
* Apply endpoint/account/device rate limits in addition to the per-challenge
  attempt counter.
* Render every grid and requested-position challenge exactly as received; do not
  normalize or reorder positions in the UI.
