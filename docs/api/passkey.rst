Passkey API
===========

``Passkey`` is available when ``web-auth/webauthn-lib`` is installed.

Constructor and capability:

.. code-block:: php

   new Passkey(
       AuthenticationStateCacheInterface $cache,
       string $rpId,
       string $rpName,
       array $allowedOrigins,
       int $ttlSeconds = 300,
       bool $allowSubdomains = false,
   );

   public static function isAvailable(): bool;

Registration:

.. code-block:: php

   public function beginRegistration(
       string $binding,
       string $userHandle,
       string $username,
       string $displayName,
       array $existingCredentialRecordsJson = [],
       ?int $now = null,
   ): PasskeyCeremony;

   public function finishRegistration(
       string $binding,
       string $ceremonyId,
       string $credentialJson,
       ?int $now = null,
   ): PasskeyResult;

Authentication:

.. code-block:: php

   public function beginAuthentication(
       string $binding,
       array $credentialRecordsJson = [],
       ?string $userHandle = null,
       ?int $now = null,
   ): PasskeyCeremony;

   public function extractCredentialId(string $credentialJson): string;

   public function finishAuthentication(
       string $binding,
       string $ceremonyId,
       string $credentialRecordJson,
       string $credentialJson,
       ?int $now = null,
   ): PasskeyResult;

``PasskeyCeremony::optionsJson`` is the serialized WebAuthn creation/request
options sent to the client. ``PasskeyResult::credentialRecordJson`` is durable
application data. Persist the returned updated record after every successful
authentication.

See :doc:`../guides/passkey`.
