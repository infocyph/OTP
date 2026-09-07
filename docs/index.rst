Infocyph OTP
============

Infocyph OTP provides framework-agnostic PHP 8.4 primitives for:

* generic email, SMS, and one-time challenges;
* HOTP counters defined by RFC 4226;
* TOTP authenticator codes defined by RFC 6238;
* OCRA challenge-response defined by RFC 6287;
* AOTP asymmetric Ed25519 one-time challenge-response;
* GridOTP dynamic-grid human challenge-response;
* single-use recovery-code batches;
* strict provisioning URI parsing and generation;
* SVG QR enrollment payloads;
* secret-rotation planning; and
* CacheLayer-backed atomic replay and consumption boundaries.

AOTP and GridOTP are Infocyph-defined protocol primitives, not RFC-standardized
OTP formats and not ``otpauth://`` authenticator schemes.

The package deliberately stops at the cryptographic and atomic-state boundary.
Your application remains responsible for encrypted secret persistence, delivery,
rate limiting, session authentication, audit, enrollment policy, recovery
policy, and user-facing error handling.

Choosing a primitive
--------------------

.. list-table::
   :header-rows: 1
   :widths: 24 22 54

   * - Scenario
     - Primitive
     - State your application owns
   * - Authenticator-app sign-in
     - ``TOTP``
     - Encrypted secret, factor generation, CacheLayer replay state
   * - Hardware token or event counter
     - ``HOTP``
     - Encrypted secret, next counter, durable CacheLayer counter state
   * - Email or SMS challenge
     - ``GenericOtp``
     - Safe CacheLayer state cache and purpose-specific HMAC key
   * - Shared-key challenge-response or signing
     - ``OCRA``
     - Suite, encrypted shared key, inputs, CacheLayer counter/replay state
   * - Public-key challenge-response
     - ``AOTP``
     - Ed25519 public key, protected client private key, CacheLayer challenge state
   * - Human dynamic-grid challenge
     - ``GridOTP``
     - Encrypted knowledge secret and locked CacheLayer challenge state
   * - Offline recovery fallback
     - ``RecoveryCodes``
     - Atomic recovery store and separate HMAC key

Documentation map
-----------------

Start with :doc:`getting-started/installation` and
:doc:`getting-started/quickstart`. Each guide includes complete configuration
bounds, lifecycle rules, result handling, failure behavior, and runnable usage
examples. Production deployments should always review :doc:`guides/security`,
:doc:`guides/storage`, and :doc:`guides/replay-protection`.

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   getting-started/installation
   getting-started/quickstart
   getting-started/migration

.. toctree::
   :maxdepth: 2
   :caption: Usage guides

   guides/application-workflows
   guides/generic-otp
   guides/hotp
   guides/totp
   guides/ocra
   guides/aotp
   guides/grid-otp
   guides/recovery-codes
   guides/provisioning
   guides/secret-rotation

.. toctree::
   :maxdepth: 2
   :caption: Operations and security

   guides/security
   guides/replay-protection
   guides/storage
   guides/custom-stores
   guides/authenticator-apps
   guides/errors-and-limits

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/protocols
   api/aotp
   api/grid-otp
   api/contracts
   api/results
   api/support
