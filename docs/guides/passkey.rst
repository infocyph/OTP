Passkey / WebAuthn
==================

``Passkey`` is an optional integration around ``web-auth/webauthn-lib``. OTP owns
short-lived ceremony state and lifecycle boundaries; the upstream library owns
WebAuthn parsing, attestation, signature, origin, RP-ID, user-verification, and
counter validation.

Installation
------------

The WebAuthn dependency is intentionally optional so HOTP/TOTP-only consumers do
not pull the WebAuthn dependency graph:

.. code-block:: bash

   composer require web-auth/webauthn-lib:^5.3

The package is present in OTP's ``require-dev`` matrix and listed under Composer
``suggest``. Constructing ``Passkey`` without it throws ``LogicException``.
Passkey does not require ``ext-sodium`` from OTP; sodium is only needed when the
application uses AOTP.

Relying-party configuration
---------------------------

.. code-block:: php

   use Infocyph\OTP\Passkey;

   $passkey = new Passkey(
       cache: $stateCache,
       rpId: 'example.com',
       allowedOrigins: ['https://example.com'],
       ttlSeconds: 300,
   );

Origins are exact by default and must contain only scheme, host, and optional
port; do not include a trailing slash or any path. ``allowSubdomains: true``
delegates subdomain acceptance to webauthn-lib. Plain HTTP is rejected except
for localhost/loopback development origins. Do not derive RP IDs or allowed
origins from untrusted request headers.

OTP currently uses the RP ID as the serialized RP display name as well. There is
no separate ``rpName`` constructor argument. This keeps the wrapper surface
small while still emitting a valid RP entity.

Ceremony state requires the same fail-closed, integrity-protected,
authoritative, coordinated-lock CacheLayer policy as other multi-field
authentication state. ``$stateCache`` in the examples below is configured as
described in :doc:`storage`.

Complete registration flow
--------------------------

A passkey registration uses a discoverable credential, requires user
verification, and requests attestation conveyance ``none``.

The authenticated server creates the registration ceremony. Use a stable opaque
user handle of 1..64 bytes; do not use an email address as the user handle when a
stable internal identifier is available.

.. code-block:: php

   use Infocyph\OTP\Passkey;

   $userId = 42;
   $binding = 'user-42:passkey:registration:flow-7f2c';
   $userHandle = 'user-42';

   $passkey = new Passkey(
       cache: $stateCache,
       rpId: 'example.com',
       allowedOrigins: ['https://example.com'],
   );

   $ceremony = $passkey->beginRegistration(
       binding: $binding,
       userHandle: $userHandle,
       username: 'alice@example.com',
       displayName: 'Alice',
       existingCredentialRecordsJson: loadCredentialRecordsForUser($userId),
   );

   // Return this JSON body from the registration-options endpoint.
   $payload = json_encode([
       'ceremonyId' => $ceremony->id,
       'options' => json_decode($ceremony->optionsJson, true, 512, JSON_THROW_ON_ERROR),
   ], JSON_THROW_ON_ERROR);

Keep ``$binding`` server-side in the authenticated enrollment flow/session. Do
not let the browser choose another account's binding.

In a modern browser, convert the JSON representation into native WebAuthn
options, create the credential, and send the returned credential JSON to the
server. These JSON helpers are standardized WebAuthn convenience methods and
operate in secure contexts:

.. code-block:: javascript

   const start = await fetch('/api/passkeys/register/options', {
     method: 'POST',
     credentials: 'same-origin',
     headers: {'Content-Type': 'application/json'},
   }).then((response) => response.json());

   const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
     start.options,
   );

   const credential = await navigator.credentials.create({publicKey});
   if (!(credential instanceof PublicKeyCredential)) {
     throw new Error('Passkey registration did not return a public-key credential.');
   }

   const finish = await fetch('/api/passkeys/register/finish', {
     method: 'POST',
     credentials: 'same-origin',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({
       ceremonyId: start.ceremonyId,
       credential,
     }),
   });

``JSON.stringify()`` invokes ``PublicKeyCredential.toJSON()`` so binary WebAuthn
fields are transported as base64url strings.

The finish endpoint reconstructs only the browser credential JSON. The original
creation options are loaded from OTP's server-side ceremony state, not accepted
back from the browser:

.. code-block:: php

   $body = json_decode(
       file_get_contents('php://input'),
       true,
       512,
       JSON_THROW_ON_ERROR,
   );

   $credentialJson = json_encode(
       $body['credential'],
       JSON_THROW_ON_ERROR,
   );

   $result = $passkey->finishRegistration(
       binding: $binding,
       ceremonyId: $body['ceremonyId'],
       credentialJson: $credentialJson,
   );

   if (!$result->matched) {
       // Return a generic registration failure to the client.
   }

   persistCredential(
       userId: $userId,
       credentialId: $result->credentialId,
       recordJson: $result->credentialRecordJson,
   );

``credentialRecordJson`` is a serialized webauthn-lib ``CredentialRecord`` and
is durable application authentication data. Store it in an authoritative
database. CacheLayer stores only the expiring ceremony.

Complete authentication flow
----------------------------

For account-bound authentication, pass the account's stored records so WebAuthn
emits ``allowCredentials``:

.. code-block:: php

   $binding = 'login-flow-9af3';
   $records = loadCredentialRecordsForUser($userId);

   $ceremony = $passkey->beginAuthentication(
       binding: $binding,
       credentialRecordsJson: $records,
       userHandle: $userHandle,
   );

For discoverable/usernameless login, omit both the record list and user handle:

.. code-block:: php

   $binding = 'login-flow-9af3';
   $ceremony = $passkey->beginAuthentication($binding);

Return ``ceremonyId`` and decoded ``optionsJson`` just as in registration. The
browser requests an assertion:

.. code-block:: javascript

   const start = await fetch('/api/passkeys/login/options', {
     method: 'POST',
     credentials: 'same-origin',
     headers: {'Content-Type': 'application/json'},
   }).then((response) => response.json());

   const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
     start.options,
   );

   const credential = await navigator.credentials.get({publicKey});
   if (!(credential instanceof PublicKeyCredential)) {
     throw new Error('Passkey authentication did not return a public-key credential.');
   }

   await fetch('/api/passkeys/login/finish', {
     method: 'POST',
     credentials: 'same-origin',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({
       ceremonyId: start.ceremonyId,
       credential,
     }),
   });

The verifier converts the returned credential to JSON and resolves the durable
record. In a discoverable flow, ``extractCredentialId()`` is only a bounded
lookup helper; it is not authentication:

.. code-block:: php

   $body = json_decode(
       file_get_contents('php://input'),
       true,
       512,
       JSON_THROW_ON_ERROR,
   );

   $credentialJson = json_encode(
       $body['credential'],
       JSON_THROW_ON_ERROR,
   );

   $credentialId = $passkey->extractCredentialId($credentialJson);
   $stored = loadCredentialById($credentialId);

   if ($stored === null || $stored->revoked) {
       // Fail with a generic authentication response.
   }

   $result = $passkey->finishAuthentication(
       binding: $binding,
       ceremonyId: $body['ceremonyId'],
       credentialRecordJson: $stored->recordJson,
       credentialJson: $credentialJson,
   );

   if (!$result->matched) {
       // Fail closed. Do not complete the login session.
   }

   updateCredentialRecord(
       credentialId: $result->credentialId,
       recordJson: $result->credentialRecordJson,
   );

   // Only now complete the authenticated session transition.

On every successful authentication, persist the returned
``credentialRecordJson`` over the old record. The WebAuthn credential counter,
backup state, and user-verification state may have changed. Never discard the
updated record.

Ceremony replay and failures
----------------------------

The complete serialized creation/request options are stored server-side under a
random 128-bit ceremony ID. Caller-supplied options are never trusted back into
the verification path. A successful verification leaves a consumed marker until
the original expiry so a concurrent or repeated response returns
``VerificationReason::Replay``.

Malformed or cryptographically invalid WebAuthn responses do not consume the
ceremony. OTP type-checks serializer results before using them so malformed
browser JSON returns ``Malformed`` rather than escaping as a PHP type error.
Corrupt stored ceremony options or durable credential records are operational
failures and fail closed.

Security boundary
-----------------

OTP does not receive or store a passkey private key. Private-key creation and use
remain in the platform authenticator/security key. The application owns:

* authenticated enrollment policy;
* user-to-credential relationships;
* durable ``CredentialRecord`` persistence;
* credential naming, disabling, and revocation;
* account recovery and factor reset;
* application/session authorization after successful verification;
* rate limiting and abuse controls; and
* audit and user notifications.

Use HTTPS in production. Keep RP ID and allowed origins in trusted deployment
configuration. Do not place ceremony options or browser credential payloads in
URLs or logs. Do not replace webauthn-lib validators with custom
COSE/CBOR/signature parsing. Passkeys are WebAuthn credentials, not
``otpauth://`` OTP seeds, and no provisioning URI is generated.
