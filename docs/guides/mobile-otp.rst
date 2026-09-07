MobileOTP
=========

``MobileOTP`` implements the legacy Mobile-OTP/mOTP protocol introduced by
Matthias Straub in 2003. It exists for interoperability with deployed mOTP
clients and servers. New deployments should prefer TOTP or Passkey; AOTP is also
available when its custom asymmetric challenge-response model fits the client.

Protocol compatibility
----------------------

The established Mobile-OTP client computes:

.. code-block:: text

   step = floor(unix_timestamp / 10)
   digest = MD5HEX(decimal(step) || init_secret || pin)
   otp = first 6 lowercase hexadecimal characters of digest

The Init-Secret is exactly 16 hexadecimal characters and the PIN is exactly four
decimal digits. ``MobileOTP::generateSecret()`` creates the canonical
16-character lowercase secret.

The Init-Secret is hashed as text, not decoded from hexadecimal. Its character
case therefore affects the result. Preserve the exact enrolled value.

Complete enrollment and verification flow
-----------------------------------------

Generate an Init-Secret on the verifier and enroll the same exact value into the
legacy mobile client. The PIN may be user-selected or provisioned according to
the consuming application's policy, but it must contain exactly four decimal
digits.

.. code-block:: php

   use Infocyph\OTP\MobileOTP;

   $secret = MobileOTP::generateSecret();
   $pin = '5555';
   $factorId = 'user-42:mobile:secret-v1';

   persistMobileOtpFactor(
       factorId: $factorId,
       encryptedSecret: encryptFactorSecret($secret),
       encryptedPin: encryptFactorPin($pin),
   );

   // Provision the exact $secret to the mOTP client through a protected flow.
   // The client also needs the four-digit PIN to calculate a code.

The following code demonstrates the client calculation at a fixed timestamp.
Using an explicit timestamp makes the example reproducible; production clients
normally omit it and use the current time.

.. code-block:: php

   use Infocyph\OTP\MobileOTP;

   $timestamp = 1_700_000_000;
   $client = new MobileOTP(
       secret: $clientSecret,
       pin: $clientPin,
   );

   $submittedOtp = $client->generate(timestamp: $timestamp);

On the verifier, load the enrolled values, construct the same protocol object,
and verify. Authentication endpoints should use CacheLayer replay protection and
a generation-specific factor ID:

.. code-block:: php

   use Infocyph\OTP\MobileOTP;
   use Infocyph\OTP\ValueObjects\VerificationWindow;
   use Infocyph\OTP\VerificationReason;

   $factor = loadMobileOtpFactor('user-42:mobile:secret-v1');
   $server = new MobileOTP(
       secret: decryptFactorSecret($factor->encryptedSecret),
       pin: decryptFactorPin($factor->encryptedPin),
   );

   $result = $server->verifyWithWindow(
       otp: $submittedOtp,
       timestamp: $timestamp,
       window: new VerificationWindow(past: 0, future: 0),
       cache: $stateCache,
       factorId: $factor->factorId,
   );

   if ($result->matched) {
       // Complete the application's authenticated session transition.
   } elseif ($result->reason === VerificationReason::Replay) {
       // This timestep, or a later one, was already accepted for the factor.
   } else {
       // Malformed, mismatched, or out-of-window code.
   }

``verify()`` is the stateless boolean convenience path. Use it only where
single-use acceptance is not required. ``verifyWithWindow()`` returns the
structured verification result and can atomically advance replay state.

Clock windows and offsets
-------------------------

The historical Mobile-OTP server commonly accepted three minutes in either
direction, which equals 18 ten-second steps. OTP uses a strict zero-window
default instead. Opt into wider compatibility only when the deployed clients
require it:

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $server->verifyWithWindow(
       otp: $submittedOtp,
       window: VerificationWindow::symmetric(18),
       cache: $stateCache,
       factorId: $factor->factorId,
   );

Windows larger than 18 steps per direction are rejected. Every additional step
widens the set of currently acceptable codes, so use the smallest window that
works for the actual client population.

``offsetSteps`` is different from an acceptance window. It applies a fixed clock
offset measured in ten-second steps before generation or verification and is
bounded to 24 hours in either direction:

.. code-block:: php

   $otp = $client->generate(offsetSteps: 2); // client treated as 20 seconds ahead

   $result = $server->verifyWithWindow(
       otp: $otp,
       offsetSteps: 2,
       cache: $stateCache,
       factorId: $factor->factorId,
   );

Use a fixed offset only when a known legacy integration requires it. Prefer
correct system time over compensating for uncontrolled drift.

Replay protection
-----------------

Replay-aware verification advances the greatest accepted MobileOTP timestep
through the same CacheLayer 3.3 monotonic state primitive used by TOTP. Native
atomics are preferred when the configured backend exposes them; otherwise the
coordinated lock fallback is used. A timestep accepted once cannot be accepted
again for the same factor generation, and an older timestep cannot overwrite a
newer accepted one.

The replay TTL covers the configured acceptance window. Cache and ``factorId``
are an all-or-nothing pair; providing only one is rejected.

Security position
-----------------

Mobile-OTP deliberately uses MD5 because MD5 is part of the established protocol
wire calculation. OTP does not use MD5 for any new design. Only the first 24 bits
of the digest are transmitted, the legacy Init-Secret is 64 bits, and the PIN is
four decimal digits.

The verifier must know both Init-Secret and PIN, so protect both as
authentication secrets and encrypt them at rest. The original phone model can
represent two factors when the device holds the Init-Secret and the user enters
the PIN locally, but a verifier database compromise that reveals both values
allows an attacker to generate valid codes.

Operational rules
-----------------

* Use MobileOTP only for interoperability with an existing mOTP deployment.
* Preserve the exact Init-Secret text and case.
* Encrypt both Init-Secret and PIN at rest on the verifier.
* Use monitored time synchronization and the smallest practical window.
* Rotate ``factorId`` whenever Init-Secret or PIN generation changes.
* Apply application rate limits; the protocol's six-hex-character output remains
  a small online-guessing space.
* Do not expose Init-Secrets, PINs, generated codes, or replay IDs in logs.

Do not use MobileOTP as the default choice for a new authentication system.
