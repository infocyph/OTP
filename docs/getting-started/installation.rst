Installation
============

Requirements
------------

The base package requires:

* PHP ``^8.4``;
* a 64-bit PHP build;
* the ``ctype`` extension;
* CacheLayer ``^4.0``; and
* Composer.

Install the current release:

.. code-block:: bash

   composer require infocyph/otp
   composer check-platform-reqs

Composer installs CacheLayer, constant-time Base32, and QR dependencies
automatically. OTP depends on CacheLayer directly and does not ask applications
to implement a second OTP-specific cache abstraction.

Optional AOTP dependency
------------------------

AOTP uses Ed25519 and therefore requires PHP's ``sodium`` extension. Sodium is
not required by HOTP, TOTP, OCRA, GenericOtp, GridOTP, MobileOTP, RecoveryCodes,
or OTP's Passkey wrapper.

OTP declares ``ext-sodium`` under Composer ``suggest`` and installs it in
``require-dev`` so AOTP is continuously tested without making the extension a
mandatory platform requirement for every consumer.

Check capability before enabling AOTP:

.. code-block:: php

   use Infocyph\OTP\AOTP;

   if (!AOTP::isAvailable()) {
       // Disable AOTP enrollment/authentication for this runtime.
   }

Constructing or using AOTP without sodium fails with ``LogicException`` rather
than silently selecting a weaker algorithm.

Optional Passkey dependency
---------------------------

Passkey/WebAuthn support uses the maintained ``web-auth/webauthn-lib`` package
instead of duplicating WebAuthn cryptography and ceremony validation:

.. code-block:: bash

   composer require web-auth/webauthn-lib:^5.3

OTP declares this dependency under Composer ``suggest`` and installs it in
``require-dev`` for its own test/static-analysis matrix. It is intentionally not
a mandatory runtime dependency because applications that only use HOTP, TOTP,
OCRA, GenericOtp, AOTP, GridOTP, MobileOTP, or recovery codes should not inherit
the WebAuthn/CBOR/PKI/Symfony dependency graph.

``Passkey::isAvailable()`` reports whether the optional package is loaded.
Constructing ``Passkey`` without it throws ``LogicException`` with the install
command. OTP's Passkey wrapper does not itself require ``ext-sodium``.

Optional Runwire dependency
---------------------------

Runwire is optional and is useful only when the host already owns a compatible
Runwire 2.1+ request/coroutine lifecycle. Install it explicitly when that
integration is required:

.. code-block:: bash

   composer require infocyph/runwire:^2.1

OTP accepts CacheLayer's existing ``RunwireExecutionContext`` as a trailing
optional ``runwire`` argument on stateful operations. When omitted, behavior
remains synchronous. OTP never discovers or starts a runtime, never binds or
releases CacheLayer's process-global Runwire integration, and never closes a
host-owned scope. See :doc:`../guides/application-workflows` for direct and
forwarded examples.

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

The second command must print ``true``. ``php -m`` must include ``ctype``. It
must also include ``sodium`` when the application enables AOTP. Counters and
timestamps depend on 64-bit integer behavior. When the application uses Passkey,
its committed application lock file must also include a compatible
``web-auth/webauthn-lib`` installation.

Production installation
-----------------------

Install from a committed lock file in an application:

.. code-block:: bash

   composer install \
       --no-dev \
       --classmap-authoritative \
       --no-interaction

This library intentionally does not ship its own lock file in release archives;
the consuming application should lock the selected package version and any
optional Passkey dependency it uses. Production images that enable AOTP must
also enable ``ext-sodium`` at the PHP platform level.

First configuration
-------------------

Generate secrets with the protocol class rather than inventing values:

.. code-block:: php

   use Infocyph\OTP\AOTP;
   use Infocyph\OTP\GridOTP;
   use Infocyph\OTP\HOTP;
   use Infocyph\OTP\MobileOTP;
   use Infocyph\OTP\OCRA;
   use Infocyph\OTP\TOTP;

   $totpSecret = TOTP::generateSecret();
   $hotpSecret = HOTP::generateSecret(32);
   $ocraSecret = OCRA::generateSecret(32);
   $gridSecret = GridOTP::generateSecret();
   $mobileOtpSecret = MobileOTP::generateSecret();

   $aotpKeys = AOTP::isAvailable()
       ? AOTP::generateKeyPair()
       : null;

HOTP, TOTP, and ``OCRA::fromBase32()`` require 16–1024 decoded bytes. Store
factor secrets encrypted and never put them in source code,
environment-variable dumps, logs, exception messages, metrics, or analytics.
Protect the AOTP private key on the client; only its public key belongs at the
verifier. GridOTP secrets must be encrypted at rest because verification needs
the enrolled secret. MobileOTP requires both its exact 16-character Init-Secret
and four-digit PIN for verification; encrypt both and preserve the Init-Secret's
character case because the legacy wire algorithm hashes its text representation.

Passkey differs from shared-secret protocols: the authenticator holds the private
key and the application stores the serialized ``CredentialRecord`` returned by
``PasskeyResult`` in an authoritative durable database. CacheLayer stores only
the short-lived WebAuthn ceremony state.

Generic OTP and recovery codes use raw purpose-specific HMAC keys instead:

.. code-block:: php

   $genericOtpKey = random_bytes(32);
   $recoveryCodeKey = random_bytes(32);

Use different keys for these two purposes. Both APIs accept 16–1024 key bytes.
Stateful Generic OTP and replay-aware HOTP/TOTP/OCRA/AOTP/MobileOTP calls require
a configured fail-closed, payload-integrity protected, authoritative CacheLayer
authentication-state cache. CacheLayer 4.0 native atomics are preferred for
scalar and whole-record transitions. GenericOtp, GridOTP, and Passkey use
whole-record CAS when available; a coordinated lock is the fallback when the
selected backend does not expose a safe atomic capability. Start with
:doc:`../guides/storage` before wiring an authentication endpoint.

Upgrading to OTP 7.0
--------------------

OTP 7.0 raises the runtime dependency floor to CacheLayer 4.0. CacheLayer 4.0
changes signed-record identity binding, so authentication-state envelopes written
by CacheLayer 3.x must not be assumed readable by 4.x or vice versa. Do not run
mixed 3.x/4.x workers against one OTP state namespace.

Use a coordinated cutover: stop old writers, let short-lived challenge/replay
records expire or invalidate them deliberately, preserve application-owned HOTP
counters and Passkey CredentialRecords, then start only the 7.0/CacheLayer-4
workers. For no-TTL monotonic replay/counter state, use a new factor generation
and factor ID when the prior signed state cannot be carried safely. Do not clear
state casually in a way that re-opens previously accepted credentials.

OTP's package-owned v1 key domains remain stable inside the 7.0 line; the
incompatibility is the CacheLayer 3.x/4.x signed storage envelope, not an
arbitrary OTP key rename. See :doc:`migration` for the full cutover and rollback
rules.

Development checks
------------------

Contributors can run the repository's complete PHPForge gate:

.. code-block:: bash

   composer install
   composer ic:process
   composer ic:tests
   composer benchmark

CI runs both ``prefer-lowest`` and ``prefer-stable`` dependency matrices. The
development matrix installs ``ext-sodium``, ``web-auth/webauthn-lib``, and
``infocyph/runwire`` through ``require-dev`` so optional integrations are
exercised while the clean ``--no-dev`` install verifies that none is required
by the base package.

Next steps
----------

Continue with :doc:`quickstart`. Before production, read
:doc:`../guides/security` and :doc:`../guides/storage`.
