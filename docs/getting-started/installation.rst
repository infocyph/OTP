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

   $totpSecret = TOTP::generateSecret();   // 20 random bytes
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
Stateful Generic OTP and replay-aware HOTP/TOTP/OCRA/AOTP calls require a
configured fail-closed, payload-integrity protected, authoritative CacheLayer
authentication-state cache. TOTP, HOTP, OCRA, and AOTP use CacheLayer 3.3 native
atomics when suitable and otherwise require the cache's coordinated lock.
``GenericOtp`` and ``GridOTP`` always require that coordinated lock because
their complete transitions are multi-field. Start with :doc:`../guides/storage`
before wiring an authentication endpoint.

Upgrading from OTP 6.0
----------------------

OTP 6.1 preserves the existing v1 replay keys and values, but an atomic-capable
6.1 worker does not coordinate replay mutation through the same lock used by a
6.0 worker. Do not run shared stateful 6.0 and atomic-path 6.1 workers through a
long rolling window. Drain or replace the 6.0 stateful workers before activating
6.1 workers against the same authentication-state backend. See
:doc:`../guides/replay-protection` for the complete rule.

AOTP and GridOTP introduce new, independently namespaced v1 state and therefore
do not collide with the HOTP/TOTP/OCRA/GenericOtp state carried forward from
6.1. Applications should nevertheless rotate factor IDs whenever an enrolled
AOTP key or GridOTP secret changes.

Development checks
------------------

Contributors can run the repository's complete PHPForge gate:

.. code-block:: bash

   composer install
   composer ic:process
   composer ic:tests
   composer benchmark

CI runs both ``prefer-lowest`` and ``prefer-stable`` dependency matrices. The
lower-bound matrix therefore exercises the CacheLayer 3.3 floor declared by the
package and verifies the required ``sodium`` platform extension.

Next steps
----------

Continue with :doc:`quickstart`. Before production, read
:doc:`../guides/security` and :doc:`../guides/storage`.
