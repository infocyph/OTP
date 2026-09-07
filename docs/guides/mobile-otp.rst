MobileOTP
=========

``MobileOTP`` implements the legacy Mobile-OTP/mOTP protocol introduced by
Matthias Straub in 2003. It exists for interoperability with deployed mOTP
clients and servers. New deployments should prefer TOTP, AOTP, or Passkey.

Protocol compatibility
----------------------

The original Mobile-OTP client computes:

.. code-block:: text

   step = floor(unix_timestamp / 10)
   digest = MD5HEX(decimal(step) || init_secret || pin)
   otp = first 6 lowercase hexadecimal characters of digest

The Init-Secret is exactly 16 hexadecimal characters and the PIN is exactly four
decimal digits. ``MobileOTP::generateSecret()`` creates the canonical 16-character
lowercase secret.

.. code-block:: php

   use Infocyph\OTP\MobileOTP;

   $mobile = new MobileOTP(
       secret: '7ac61d4736f51a2b',
       pin: '5555',
   );

   $otp = $mobile->generate();
   $valid = $mobile->verify($submittedOtp);

The secret is hashed as text, not decoded from hexadecimal. Its character case
therefore affects the result. Preserve the exact enrolled value.

Clock windows and offsets
-------------------------

The original server accepted three minutes in either direction, which equals 18
ten-second steps. OTP uses a strict zero-window default instead. Opt into legacy
tolerance explicitly:

.. code-block:: php

   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $result = $mobile->verifyWithWindow(
       otp: $submittedOtp,
       window: VerificationWindow::symmetric(18),
   );

Windows larger than 18 steps per direction are rejected. ``offsetSteps`` is a
separate fixed clock-offset adjustment measured in ten-second steps and is
bounded to 24 hours in either direction.

Replay protection
-----------------

Stateless verification mirrors TOTP's boolean compatibility path. Authentication
endpoints should pass a CacheLayer authentication-state cache and a
factor-generation-specific ID:

.. code-block:: php

   $result = $mobile->verifyWithWindow(
       otp: $submittedOtp,
       cache: $stateCache,
       factorId: 'user-42:mobile:v1',
   );

The greatest accepted MobileOTP timestep is advanced atomically through the same
CacheLayer 3.3 primitive used by TOTP. A timestep accepted once cannot be
accepted again for that factor generation.

Security position
-----------------

Mobile-OTP deliberately uses MD5 because MD5 is part of the established protocol
wire calculation. OTP does not use MD5 for any new design. Only the first 24 bits
of the digest are transmitted, the legacy Init-Secret is 64 bits, and the PIN is
four decimal digits. The verifier must know both Init-Secret and PIN, so protect
them as authentication secrets and encrypt them at rest.

The original phone model can represent two factors when the device holds the
Init-Secret and the user enters the PIN locally. A verifier database compromise
that reveals both values allows an attacker to generate valid codes. Do not use
MobileOTP as the default choice for new applications.
