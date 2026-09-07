Installation
============

Requirements
------------

The package requires:

* PHP ``^8.4``;
* a 64-bit PHP build;
* the ``ctype`` extension;
* the ``sodium`` extension;
* CacheLayer ``^3.3``; and
* Composer.

Install the current release:

.. code-block:: bash

   composer require infocyph/otp
   composer check-platform-reqs

Composer installs CacheLayer, constant-time Base32, and QR dependencies
automatically. OTP depends on CacheLayer directly and does not ask applications
to implement a second OTP-specific cache abstraction. ``ext-sodium`` supplies
AOTP's Ed25519 operations.

Autoloading
-----------

Composer registers the ``Infocyph\OTP\`` namespace. Load Composer once in a
standalone application:

.. code-block:: php

   <?php

   declare(strict_types=1);

   require __DIR__ . '/vendor/autoload.php';

   use Infocyph\OTP\TOTP;

   $totp = new TOTP(TOTP::generateSecret());

Framework applications normally load Composer through their bootstrap and only
need the relevant ``use`` declarations.

Platform verification
---------------------

Check the production image, not only the development machine:

.. code-block:: bash

   php -v
   php -r "var_export(PHP_INT_SIZE === 8);"
   php -m
   composer check-platform-reqs --no-dev

The second command must print ``true``. ``php -m`` must include ``ctype`` and
``sodium``. Counters and timestamps depend on 64-bit integer behavior.

Production installation
-----------------------

Install from a committed lock file in an application:

.. code-block:: bash

   composer install \
       --no-dev \
       --classmap-authoritative \
       --no-interaction

This library intentionally does not ship its own lock file in release archives;
the consuming application should lock the selected package version.

First configuration
-------------------

Generate secrets with the protocol class rather than inventing a Base32 value:

.. code-block:: php

   use Infocyph\OTP\AOTP;
   use Infocyph\OTP\GridOTP;
   use Infocyph\OTP\HOTP;
   use Infocyph\OTP\OCRA;
   use Infocyph\OTP\TOTP;

   $totpSecret = TOTP::generateSecret();
   $hotpSecret = HOTP::generateSecret(32);
   $ocraSecret = OCRA::generateSecret(32);
   $aotpKeys = AOTP::generateKeyPair();
   $gridSecret = GridOTP::generateSecret();

HOTP, TOTP, and ``OCRA::fromBase32()`` require 16–1024 decoded bytes. Store
factor secrets encrypted and never put them in source code,
environment-variable dumps, logs, exception messages, metrics, or analytics.
Protect the AOTP private key on the client; only its public key belongs at the
verifier. GridOTP secrets must be encrypted at rest because verification needs
the enrolled secret.

Generic OTP and recovery codes use raw purpose-specific HMAC keys instead:

.. code-block:: php

   $genericOtpKey = random_bytes(32);
   $recoveryCodeKey = random_bytes(32);

Use different keys for these two purposes. Both APIs accept 16–1024 key bytes.
Stateful authentication requires a fail-closed, payload-integrity protected,
authoritative CacheLayer authentication-state cache. TOTP, HOTP, OCRA, and AOTP
can use CacheLayer 3.3 native atomics where suitable. ``GenericOtp`` and
``GridOTP`` require the coordinated lock because their complete transition is
multi-field.

Development checks
------------------

Contributors can run the repository's complete PHPForge gate:

.. code-block:: bash

   composer install
   composer ic:process
   composer ic:tests
   composer benchmark

CI runs both ``prefer-lowest`` and ``prefer-stable`` dependency matrices.

Next steps
----------

Continue with :doc:`quickstart`. Before production, read
:doc:`../guides/security` and :doc:`../guides/storage`.
