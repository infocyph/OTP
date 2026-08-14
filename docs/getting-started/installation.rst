Installation
============

Requirements are PHP ``^8.4``, a 64-bit PHP build, ``ext-ctype``, and Composer.

.. code-block:: bash

   composer require infocyph/otp
   composer check-platform-reqs

The QR and constant-time Base32 dependencies are installed automatically.
Generic OTP no longer uses PSR-6; authentication-critical transitions use the
package's atomic store contracts.
