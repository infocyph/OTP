Support Components
==================

The support layer provides focused utilities instead of one large shared trait.

Available components
--------------------

- ``Infocyph\OTP\Support\AlgorithmValidator``
- ``Infocyph\OTP\Support\SecretUtility``
- ``Infocyph\OTP\Support\LabelHelper``
- ``Infocyph\OTP\Support\OtpMath``
- ``Infocyph\OTP\Support\ProvisioningUriBuilder``
- ``Infocyph\OTP\Support\ProvisioningUriParser``
- ``Infocyph\OTP\Support\SvgQrRenderer``
- ``Infocyph\OTP\Support\StepUp``

Value objects
-------------

- ``Infocyph\OTP\ValueObjects\VerificationWindow``
- ``Infocyph\OTP\ValueObjects\ParsedOtpAuthUri``
- ``Infocyph\OTP\ValueObjects\EnrollmentPayload``
- ``Infocyph\OTP\ValueObjects\OcraSuite``
- ``Infocyph\OTP\ValueObjects\DeviceEnrollment``
- ``Infocyph\OTP\ValueObjects\SecretRotation``

Notable helper responsibilities
-------------------------------

``StepUp``
~~~~~~~~~~

Provides small policy helpers for “fresh OTP required” decisions:

- ``requiresFreshOtp()``
- ``verifiedWithin()``
- ``ageInSeconds()``
- ``assess()``

``DeviceEnrollment``
~~~~~~~~~~~~~~~~~~~~

Provides a lightweight lifecycle model for factor enrollment records:

- ``create()``
- ``activate()``
- ``revoke()``
- ``rename()``
- ``withSecretReference()``
- ``isPendingActivation()``
- ``isActive()``
- ``isRevoked()``
