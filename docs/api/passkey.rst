Passkey API
===========

``Passkey`` is available when ``web-auth/webauthn-lib`` is installed. The
optional WebAuthn integration does not require ``ext-sodium`` from OTP.

Constructor and capability
--------------------------

.. code-block:: php

   new Passkey(
       AuthenticationStateCacheInterface $cache,
       string $rpId,
       array $allowedOrigins,
       int $ttlSeconds = 300,
       bool $allowSubdomains = false,
   );

   public static function isAvailable(): bool;

``rpId`` is a host name without scheme or path. OTP uses that RP ID as the
serialized RP display name as well; there is no separate ``rpName`` constructor
argument. ``allowedOrigins`` contains exact HTTP(S) origins. Non-local HTTP is
rejected. The default ceremony TTL is 300 seconds and may be configured from 1
to 600 seconds.

Registration
------------

.. code-block:: php

   public function beginRegistration(
       string $binding,
       #[\SensitiveParameter] string $userHandle,
       string $username,
       string $displayName,
       array $existingCredentialRecordsJson = [],
       ?int $now = null,
   ): PasskeyCeremony;

   public function finishRegistration(
       string $binding,
       string $ceremonyId,
       #[\SensitiveParameter] string $credentialJson,
       ?int $now = null,
   ): PasskeyResult;

Registration requests a discoverable credential, requires user verification,
and sets attestation conveyance to ``none``. ``userHandle`` must contain 1..64
bytes. Username and display name must be valid UTF-8 and contain 1..255 bytes.
Existing serialized ``CredentialRecord`` values are converted into
``excludeCredentials`` and are limited to 64 records.

Authentication
--------------

.. code-block:: php

   public function beginAuthentication(
       string $binding,
       array $credentialRecordsJson = [],
       #[\SensitiveParameter] ?string $userHandle = null,
       ?int $now = null,
   ): PasskeyCeremony;

   public function extractCredentialId(
       #[\SensitiveParameter] string $credentialJson,
   ): string;

   public function finishAuthentication(
       string $binding,
       string $ceremonyId,
       #[\SensitiveParameter] string $credentialRecordJson,
       #[\SensitiveParameter] string $credentialJson,
       ?int $now = null,
   ): PasskeyResult;

Passing stored records emits ``allowCredentials`` for account-bound login.
Passing an empty record list and null user handle creates a discoverable/
usernameless request. ``extractCredentialId()`` only parses the browser payload
for durable record lookup; it does not authenticate the credential.

Value and result objects
------------------------

``PasskeyCeremony`` contains:

* random 128-bit URL-safe ceremony ID;
* ceremony type (registration or authentication);
* serialized WebAuthn creation/request options; and
* absolute expiration.

``PasskeyResult`` reports whether the ceremony matched and may include:

* the normalized credential ID;
* serialized durable ``CredentialRecord`` JSON;
* normalized user handle; and
* replay/malformed/mismatch status.

``PasskeyCeremony::optionsJson`` is sent to the browser. The complete options are
also retained server-side in CacheLayer and are the options used for validation;
caller-supplied replacement options are not accepted by the finish methods.

``PasskeyResult::credentialRecordJson`` is durable application data. Persist the
returned record after registration and overwrite the old record after every
successful authentication because WebAuthn counter/backup/verification state may
have changed.

State and limits
----------------

* bindings: 1..190 bytes;
* ceremony ID: 128 random bits encoded with URL-safe Base64;
* TTL: 1..600 seconds;
* browser/record JSON input: 1..131072 bytes each;
* allowed origins: 1..16 unique origins;
* credential record lists: at most 64 records;
* user handle: 1..64 bytes;
* username/display name: valid UTF-8, 1..255 bytes.

Passkey requires a fail-closed, payload-integrity protected, authoritative
CacheLayer authentication-state cache with coordinated locking. Successful
ceremonies remain marked consumed until their original expiration so duplicate
submissions can return replay.

See :doc:`../guides/passkey` for complete server and browser registration and
authentication examples.
