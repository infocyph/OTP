OTP Documentation
=================

Standalone OTP and MFA primitives for PHP.

The library includes:

- TOTP (RFC6238)
- HOTP (RFC4226)
- OCRA (RFC6287)
- Generic OTP backed by PSR-6 cache storage
- Recovery / backup codes
- Replay protection contracts and in-memory stores
- ``otpauth://`` provisioning URI generation and parsing

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started/installation
   getting-started/quickstart
   getting-started/migration

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/totp
   guides/hotp
   guides/generic-otp
   guides/ocra
   guides/provisioning
   guides/authenticator-apps
   guides/secret-rotation
   guides/device-enrollment
   guides/replay-protection
   guides/recovery-codes
   guides/step-up-auth
   guides/storage
   guides/custom-stores

.. toctree::
   :maxdepth: 2
   :caption: API

   api/results
   api/support
   api/contracts

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
