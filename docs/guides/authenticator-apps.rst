Authenticator App Compatibility
================================

Overview
--------

Not every authenticator app supports the same OTP modes or provisioning options.

This matters because:

- some apps are primarily built for TOTP
- some apps also support HOTP
- OCRA support is uncommon in mainstream consumer authenticator apps
- some apps may ignore non-default provisioning parameters such as algorithm, digit count, or period

As of April 20, 2026, the safest cross-app default is still:

- TOTP
- SHA1
- 6 digits
- 30 second period
- standard ``otpauth://`` label and issuer formatting

If you want the broadest compatibility, start there.

Practical guidance
------------------

Use TOTP for the default mobile-app path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TOTP remains the most interoperable option across mainstream mobile authenticator apps.

If you are provisioning a typical user-facing MFA app, prefer:

.. code-block:: php

   $uri = $totp->getProvisioningUri('alice@example.com', 'Example App');

Use HOTP only when the app and server flow both expect it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HOTP is supported by some authenticators, but it is less common in ordinary consumer setups than TOTP.

Choose HOTP only when:

- your server flow is explicitly counter-based
- the target app or device is known to support HOTP
- you are prepared to persist counter state and resynchronization logic

Treat OCRA as a specialized flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OCRA is not something you should assume a mainstream consumer authenticator app will support.

In practice, OCRA often needs:

- a dedicated vendor app
- a banking or enterprise authenticator
- a custom application that explicitly implements the required suite

Inference from the official app sources listed below:

- mainstream apps commonly document TOTP
- several also document HOTP
- the reviewed public docs did not clearly document mainstream OCRA support

Be careful with non-default parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Even when an app supports TOTP or HOTP, it may not fully honor every provisioning parameter.

Examples of parameters that can be problematic across apps:

- ``algorithm`` such as ``SHA256`` or ``SHA512``
- ``digits`` such as ``8`` instead of ``6``
- ``period`` values other than ``30``

If you use non-default values, test with the specific app your users will use.

App notes
---------

Google Authenticator
~~~~~~~~~~~~~~~~~~~~

Google's published open-source project and wiki document HOTP and TOTP support.

Historical Google Authenticator key-URI documentation also notes that some provisioning parameters may be ignored by Google Authenticator implementations, including:

- ``algorithm``
- ``digits`` on some implementations
- ``period``

Practical guidance:

- good baseline target for standard TOTP
- HOTP is historically documented
- do not assume non-default algorithm, digits, or period will be honored without testing

Microsoft Authenticator
~~~~~~~~~~~~~~~~~~~~~~~

Microsoft's official support pages clearly document one-time password usage for Microsoft and non-Microsoft accounts.

However, the reviewed Microsoft support pages do not clearly document:

- HOTP support details
- OCRA support
- custom algorithm handling
- custom period handling

Practical guidance:

- treat Microsoft Authenticator as a TOTP-focused target unless you have tested your exact flow
- avoid assuming support for OCRA or unusual provisioning settings

Authy
~~~~~

Current official Authy and Twilio support material reviewed for this page is more focused on platform support, backups, sync, and product lifecycle than on detailed OTP-mode compatibility.

The reviewed official material did not clearly document:

- HOTP support details
- OCRA support
- custom algorithm handling
- custom period handling

Practical guidance:

- treat Authy as a TOTP-oriented authenticator unless you have directly tested your exact provisioning profile
- do not assume HOTP or OCRA support from the current official support pages alone
- note that the Authy Desktop app reached end of life on March 19, 2024, so device guidance should focus on currently supported mobile platforms

2FAS Auth
~~~~~~~~~

2FAS documents TOTP directly and also states it can be used for services that support TOTP or HOTP tokens.

Practical guidance:

- strong fit for standard TOTP
- HOTP is mentioned in official 2FAS support material
- still test any non-default algorithm or period choices in your own target flow

Proton Authenticator
~~~~~~~~~~~~~~~~~~~~

Proton's current public documentation describes Proton Authenticator as a TOTP authenticator and repeatedly refers to time-based one-time password codes.

The reviewed Proton documentation did not clearly document:

- HOTP support
- OCRA support
- custom algorithm handling beyond the standard consumer authenticator flow

Practical guidance:

- treat Proton Authenticator as a TOTP-focused target
- it is a strong fit when you want cross-platform availability, including desktop clients
- do not assume HOTP or OCRA support unless Proton documents it clearly or you validate it directly in your own test matrix

Aegis
~~~~~

The official Aegis project documents support for:

- HOTP
- TOTP

Practical guidance:

- good choice when you need an app with clearly documented HOTP and TOTP support
- still verify advanced parameter behavior for your own provisioning profile

FreeOTP
~~~~~~~

The official FreeOTP site and Android repository document support for:

- HOTP
- TOTP

Practical guidance:

- suitable for standards-based HOTP and TOTP deployments
- like other apps, test custom algorithm or period choices before relying on them

Protectimus Smart OTP
~~~~~~~~~~~~~~~~~~~~~

Protectimus publishes much more explicit compatibility guidance than many mainstream authenticator apps.

Their public user guide states support for all OATH OTP generation algorithms, specifically:

- HOTP
- TOTP
- OCRA

The same guide also documents manual token setup with:

- OTP type selection
- one-time password length
- lifetime

Practical guidance:

- strong candidate when you need broader OTP-family support beyond standard TOTP
- especially relevant for HOTP or OCRA deployments
- still validate your exact suite and provisioning values, especially for advanced OCRA flows

Recommended compatibility tiers
-------------------------------

Broadest compatibility
~~~~~~~~~~~~~~~~~~~~~~

Use this if you want the least support friction across common mobile apps:

- TOTP
- SHA1
- 6 digits
- 30 second period

Broader standards support, but verify the app
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use this only if you control the supported app list:

- HOTP
- TOTP with non-default digits
- TOTP with non-default algorithm
- TOTP with non-default period

Specialized deployment
~~~~~~~~~~~~~~~~~~~~~~

Use this when you have a known compatible client or a dedicated enterprise flow:

- OCRA
- custom challenge workflows
- suite-specific banking or enterprise authenticators

What this means for this library
--------------------------------

If you are building for general consumer authenticator apps, prefer:

- ``TOTP``
- default provisioning values
- standard ``otpauth://`` URIs

If you are building for a controlled client environment, this library can also support:

- HOTP
- OCRA
- non-default algorithms and provisioning values

But at that point, compatibility becomes a product decision, not just a library decision.

Sources checked
---------------

The following official or project-maintained sources were reviewed on April 20, 2026:

- Google Authenticator open-source project: https://github.com/google/google-authenticator
- Google Authenticator wiki home: https://github.com/google/google-authenticator/wiki
- Google Authenticator key URI format wiki: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- Google Account Help for Google Authenticator: https://support.google.com/accounts/answer/1066447
- Microsoft Authenticator overview: https://support.microsoft.com/en-US/authenticator/about-microsoft-authenticator
- Microsoft account setup/authenticator docs: https://support.microsoft.com/en-us/account-billing/how-to-add-your-accounts-to-microsoft-authenticator-92544b53-7706-4581-a142-30344a2a2a57
- 2FAS app compatibility and support pages: https://2fas.com/support/2fas-auth-mobile-app/can-i-use-2fas-on-my-own-website-or-app/ and https://2fas.com/support/2fas-auth-mobile-app/how-does-the-2fas-app-work/
- 2FAS app tutorial: https://2fas.com/support/2fas-auth-mobile-app/2fas-auth-app-tutorial/
- Aegis project page: https://github.com/beemdevelopment/Aegis
- FreeOTP site: https://freeotp.github.io/
- FreeOTP Android repository: https://github.com/freeotp/freeotp-android
- Authy help page: https://www.authy.com/help/
- Twilio Authy system requirements: https://help.twilio.com/articles/19753636949275-Authy-App-System-Requirements
- Proton Authenticator announcement: https://proton.me/blog/authenticator-app
- Proton Authenticator support hub: https://proton.me/support/authenticator
- Proton Authenticator security model: https://proton.me/blog/authenticator-security-model
- Protectimus Smart OTP user guide: https://www.protectimus.com/guides/protectimus-smart-otp/
- Protectimus Smart OTP product page: https://www.protectimus.com/protectimus-smart/
