Authenticator compatibility
===========================

Authenticator applications implement an ecosystem convention around
``otpauth://`` URIs. Support varies by product and release. Test the exact client
versions, platforms, and migration/export flows used by your deployment.

Recommended baseline
--------------------

The most portable starting profile is:

.. code-block:: php

   $totp = new \Infocyph\OTP\TOTP(
       secret: \Infocyph\OTP\TOTP::generateSecret(),
       digits: 6,
       period: 30,
       algorithm: 'sha1',
   );

Its URI omits algorithm, digit, and period parameters because those are common
defaults.

Compatibility risk matrix
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - Feature
     - Expected portability
     - Required validation
   * - TOTP SHA-1 / 6 / 30
     - Broadest
     - Enrollment, code generation, export/import
   * - TOTP SHA-256 or SHA-512
     - Variable
     - Algorithm honored rather than ignored
   * - TOTP 7–9 digits
     - Variable
     - Display width and verification
   * - Non-30-second period
     - Variable
     - Period honored and countdown correct
   * - HOTP
     - Variable
     - Counter import, advancement, resynchronization
   * - Additional URI parameters
     - Variable
     - Unknown values preserved/ignored safely
   * - OCRA URI
     - Specialized
     - Exact suite and client-specific enrollment support
   * - SVG scanning
     - Usually broad
     - Image size, contrast, browser rendering

Test plan
---------

For every supported client:

#. enroll from a freshly generated URI/QR;
#. verify at least two consecutive codes;
#. verify digits, period, and algorithm are actually honored;
#. test labels with representative Unicode and account formats;
#. test device clock drift within the application's window;
#. export/import or device migration if promised to users;
#. rotate a factor and confirm old/new overlap policy;
#. remove the factor and verify old codes fail; and
#. repeat after significant client releases.

HOTP-specific tests
-------------------

Confirm that the client begins at the exact provisioned counter, advances when
a code is displayed/used according to its behavior, and can recover within the
server look-ahead. Do not assume all clients expose HOTP clearly to users.

OCRA-specific warning
---------------------

RFC 6287 defines calculation, not an ``otpauth://ocra`` enrollment standard.
This library's URI is a convention for integrations that explicitly understand
it. Do not show a generic authenticator-app QR and assume OCRA support.

Minimal URIs
------------

The convenience methods emit minimal default TOTP URIs and required protocol
fields automatically. Additional parameters can reduce interoperability. Add
only parameters consumed by clients you have tested.

Operational guidance
--------------------

Client behavior can change independently of this package. Maintain a supported
client/version policy, a test device matrix, and a user-facing fallback path.
Do not advertise compatibility based only on successful QR scanning; verify the
generated codes and lifecycle behavior.
