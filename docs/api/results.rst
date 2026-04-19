Result Objects
==============

VerificationResult
------------------

Used by advanced verification flows in TOTP, HOTP, and OCRA.

Fields:

- ``matched``
- ``reason``
- ``matchedTimestep``
- ``matchedCounter``
- ``driftOffset``
- ``replayDetected``
- ``verifiedAt``

RecoveryCodeGenerationResult
----------------------------

Fields:

- ``plainCodes``
- ``totalGenerated``
- ``remainingCount``
- ``lastUsedAt``

RecoveryCodeConsumptionResult
-----------------------------

Fields:

- ``consumed``
- ``reason``
- ``remainingCount``
- ``totalGenerated``
- ``lastUsedAt``

StepUpResult
------------

Returned by ``Infocyph\OTP\Support\StepUp::assess()``.

Fields:

- ``requiresFreshOtp``
- ``verifiedAt``
- ``ageInSeconds``
- ``freshForSeconds``
- ``expiresAt``
