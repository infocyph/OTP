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

A secret can contain 8..32 symbols. ``generateSecret()`` now guarantees at least
``min(10, length)`` distinct symbols, so every supported challenge size can
select distinct enrolled symbols when the generated secret is used. The default
12-symbol secret remains the recommended general-purpose profile. Rotating the
secret must create a new factor generation and factor ID.

For new enrollment, opt into diversity enforcement so imported or manually
supplied secrets receive the same minimum policy:

.. code-block:: php

   $gridOtp = new GridOTP(
       cache: $stateCache,
       secret: $secret,
       challengeSize: 6,
       enforceDiversity: true,
   );

``enforceDiversity`` is deliberately ``false`` by default in 6.2 so an upgrade
does not silently lock out an already-enrolled weak factor. New deployments
should enable it after enrollment and migration policy is in place.

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

Response length is **not** the same as independent guessing entropy. A legacy
secret such as ``AAAAAAAA`` makes every requested position refer to the same
secret symbol; a six-digit response then has only one mapped digit repeated six
times. With the balanced 32-symbol grid and a uniform prior over that unknown
symbol, the most likely digit has probability ``4/32 = 1/8``. Application/user
choice can make the real prior worse, so this is not a security guarantee.

When the enrolled secret contains enough distinct symbols, GridOTP 6.2 chooses
challenge positions whose secret symbols are distinct. The decimal grid still
maps multiple symbols to the same label, so response digits are not guaranteed
to be distinct. Under an idealized model of uniformly unknown distinct secret
symbols, the most likely exact six-position label sequence is about 1 in
503,440 (18.94 bits); for ten positions it is about 1 in 2.23 billion
(31.05 bits). These figures describe that model only, not arbitrary custom
secrets or a substitute for endpoint rate limits.

It is not shoulder-surfing proof. An observer who repeatedly captures the full
grid, requested positions, and submitted responses can intersect candidate sets
and eventually recover secret symbols. Treat GridOTP as one knowledge factor,
not MFA. Prefer standards-based Passkey/WebAuthn when phishing-resistant public-
key authentication is available and appropriate.

Migrating existing factors
--------------------------

Inventory existing encrypted secrets before enabling strict enforcement:

.. code-block:: php

   if (!GridOTP::hasSufficientDiversity($serverSecret, challengeSize: 6)) {
       markGridFactorForReenrollment($factorId);
   }

Keep the legacy factor working during the migration window, re-enroll it with a
fresh ``generateSecret()`` value and a new factor ID, then construct the new
generation with ``enforceDiversity: true``. Do not silently regenerate or replace
a user's existing secret during a library upgrade.

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
