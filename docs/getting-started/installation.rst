Installation
============

Requirements
------------

- PHP 8.4 or newer

Install from Packagist:

.. code-block:: bash

   composer require infocyph/otp

Included capabilities
---------------------

- Base32 secret generation, normalization, and validation
- TOTP verification with configurable drift windows
- HOTP look-ahead verification and resynchronization helpers
- OCRA generation and verification
- Generic OTP with caller-provided PSR-6 cache storage
- Recovery codes with hashed storage
- Provisioning URI generation, parsing, and SVG QR rendering

Testing locally
---------------

.. code-block:: bash

   php vendor/bin/pest
