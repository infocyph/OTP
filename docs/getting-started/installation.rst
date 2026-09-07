Installation
============

Requirements
------------

The package requires:

* PHP ``^8.4``;
* a 64-bit PHP build;
* the ``ctype`` extension;
* CacheLayer ``^3.3``; and
* Composer.

Install the current release:

.. code-block:: bash

   composer require infocyph/otp
   composer check-platform-reqs

Composer installs CacheLayer, constant-time Base32, and QR dependencies
automatically. OTP depends on CacheLayer directly and does not ask applications
to implement a second OTP-specific cache abstraction.

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

The second command must print ``true``. Counters and timestamps depend on 64-bit
integer behavior.

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

   use Infocyph\OTP\HOTP;
   use Infocyph\OTP\OCRA;
   use Infocyph\OTP\TOTP;

   $totpSecret = TOTP::generateSecret();   // 20 random bytes
   $hotpSecret = HOTP::generateSecret(32);
   $ocraSecret = OCRA::generateSecret(32);

HOTP, TOTP, and ``OCRA::fromBase32()`` require 16–1024 decoded bytes. Store
factor secrets encrypted and never put them in source code,
environment-variable dumps, logs, exception messages, metrics, or analytics.

Generic OTP and recovery codes use raw purpose-specific HMAC keys instead:

.. code-block:: php

   $genericOtpKey = random_bytes(32);
   $recoveryCodeKey = random_bytes(32);

Use different keys for these two purposes. Both APIs accept 16–1024 key bytes.
Stateful Generic OTP and replay-aware HOTP/TOTP/OCRA calls require a configured
fail-closed, payload-integrity protected, authoritative CacheLayer
authentication-state cache. TOTP, HOTP, and OCRA use CacheLayer 3.3 native
atomics when available and otherwise require the cache's coordinated lock.
``GenericOtp`` always requires that coordinated lock in OTP 6.1. Start with
:doc:`../guides/storage` before wiring an authentication endpoint.

Upgrading from OTP 6.0
----------------------

OTP 6.1 preserves the existing v1 replay keys and values, but an atomic-capable
6.1 worker does not coordinate replay mutation through the same lock used by a
6.0 worker. Do not run shared stateful 6.0 and atomic-path 6.1 workers through a
long rolling window. Drain or replace the 6.0 stateful workers before activating
6.1 workers against the same authentication-state backend. See
:doc:`../guides/replay-protection` for the complete rule.

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
package.

Next steps
----------

Continue with :doc:`quickstart`. Before production, read
:doc:`../guides/security` and :doc:`../guides/storage`.
