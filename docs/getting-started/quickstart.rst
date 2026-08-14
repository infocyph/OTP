Quickstart
==========

Start with the interoperable TOTP defaults:

.. code-block:: php

   $totp = new \Infocyph\OTP\TOTP(\Infocyph\OTP\TOTP::generateSecret());
   $uri = $totp->getProvisioningUri('alice@example.com', 'Example App');
   $valid = $totp->verify($submittedCode);

Use SHA-256 only when the target authenticator is known to support it:

.. code-block:: php

   $totp = new \Infocyph\OTP\TOTP($secret, algorithm: 'sha256');

Provisioning URIs and QR SVGs contain the factor secret. Never log them.
