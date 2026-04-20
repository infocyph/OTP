Device Enrollment and Revocation
================================

Overview
--------

The package includes a lightweight ``DeviceEnrollment`` value object for factor enrollment records.

It is intentionally not a full device-management system. Applications are expected to persist enrollment rows in their own database.

Creating an enrollment record
----------------------------

.. code-block:: php

   <?php
   use Infocyph\OTP\ValueObjects\DeviceEnrollment;

   $enrollment = DeviceEnrollment::create(
       deviceId: 'device-1',
       label: 'Alice iPhone',
       secretReference: 'secret-ref-001',
   );

   $enrollment->isPendingActivation();

Activation after first successful verification
----------------------------------------------

.. code-block:: php

   <?php
   $activated = $enrollment->activate();

   $activated->isActive();

Renaming and reprovisioning
---------------------------

.. code-block:: php

   <?php
   $renamed = $activated->rename('Primary phone');
   $rotated = $renamed->withSecretReference('secret-ref-002');

   $rotated->label;
   $rotated->secretReference;

Revocation
----------

.. code-block:: php

   <?php
   $revoked = $rotated->revoke();

   $revoked->isRevoked();
   $revoked->isActive();

Recommended persistence fields
------------------------------

- ``device_id``
- ``user_id`` or another subject binding
- ``label``
- ``secret_reference``
- ``created_at``
- ``activated_at``
- ``revoked_at``

Recommended application flow
----------------------------

1. Create the enrollment record as pending.
2. Generate the initial provisioning payload and QR for the device.
3. Ask the user to submit the first OTP from that device.
4. Mark the enrollment active only after that verification succeeds.
5. Revoke the enrollment when the device is lost, replaced, or retired.
