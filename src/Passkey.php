<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\Result\PasskeyResult;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\PasskeyCeremony;
use InvalidArgumentException;
use LogicException;
use RuntimeException;
use Symfony\Component\Serializer\Exception\ExceptionInterface as SerializerException;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class Passkey
{
    private const int CEREMONY_ATTEMPTS = 4;

    private const int MAX_BINDING_LENGTH = 190;

    private const int MAX_CREDENTIAL_JSON_LENGTH = 131072;

    private const int MAX_CREDENTIALS = 64;

    private const int MAX_TTL_SECONDS = 600;

    private AuthenticatorAssertionResponseValidator $assertionValidator;

    private AuthenticatorAttestationResponseValidator $attestationValidator;

    private SerializerInterface $serializer;

    /**
     * @param list<string> $allowedOrigins Exact WebAuthn origins, including scheme and optional port.
     */
    public function __construct(
        private AuthenticationStateCacheInterface $cache,
        private string $rpId,
        private string $rpName,
        array $allowedOrigins,
        private int $ttlSeconds = 300,
        bool $allowSubdomains = false,
    ) {
        self::requireDependency();
        self::assertRelyingParty($rpId, $rpName);
        self::assertOrigins($allowedOrigins);
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('Passkey ceremony TTL must be between 1 and 600 seconds.');
        }
        CacheLock::assertLockSafe($cache);

        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($allowedOrigins, $allowSubdomains);
        $this->assertionValidator = new AuthenticatorAssertionResponseValidator($factory->requestCeremony());
        $this->attestationValidator = new AuthenticatorAttestationResponseValidator($factory->creationCeremony());
        $this->serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public static function isAvailable(): bool
    {
        return class_exists(CeremonyStepManagerFactory::class)
            && class_exists(WebauthnSerializerFactory::class);
    }

    /**
     * @param list<string> $credentialRecordsJson Serialized WebAuthn CredentialRecord values used as allowCredentials.
     */
    public function beginAuthentication(
        string $binding,
        array $credentialRecordsJson = [],
        #[\SensitiveParameter]
        ?string $userHandle = null,
        ?int $now = null,
    ): PasskeyCeremony {
        self::assertBinding($binding);
        if ($userHandle !== null) {
            self::assertUserHandle($userHandle);
        }
        $descriptors = $this->credentialDescriptors($credentialRecordsJson);
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->rpId,
            allowCredentials: $descriptors,
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: $this->ttlSeconds * 1000,
        );

        return $this->issueCeremony(
            $binding,
            PasskeyCeremony::TYPE_AUTHENTICATION,
            $this->serializeObject($options),
            $userHandle,
            $now,
        );
    }

    /**
     * @param list<string> $existingCredentialRecordsJson Serialized WebAuthn CredentialRecord values used as excludeCredentials.
     */
    public function beginRegistration(
        string $binding,
        #[\SensitiveParameter]
        string $userHandle,
        string $username,
        string $displayName,
        array $existingCredentialRecordsJson = [],
        ?int $now = null,
    ): PasskeyCeremony {
        self::assertBinding($binding);
        self::assertUserHandle($userHandle);
        self::assertUserName($username, 'Passkey username');
        self::assertUserName($displayName, 'Passkey display name');
        $exclude = $this->credentialDescriptors($existingCredentialRecordsJson);
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId),
            user: PublicKeyCredentialUserEntity::create($username, $userHandle, $displayName),
            challenge: random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $exclude,
            timeout: $this->ttlSeconds * 1000,
        );

        return $this->issueCeremony(
            $binding,
            PasskeyCeremony::TYPE_REGISTRATION,
            $this->serializeObject($options),
            $userHandle,
            $now,
        );
    }

    public function extractCredentialId(#[\SensitiveParameter] string $credentialJson): string
    {
        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null) {
            throw new InvalidArgumentException('Malformed WebAuthn credential payload.');
        }

        return self::encode($credential->rawId);
    }

    public function finishAuthentication(
        string $binding,
        string $ceremonyId,
        #[\SensitiveParameter]
        string $credentialRecordJson,
        #[\SensitiveParameter]
        string $credentialJson,
        ?int $now = null,
    ): PasskeyResult {
        self::assertBinding($binding);
        self::assertCeremonyId($ceremonyId);
        self::assertCredentialJsonLength($credentialRecordJson);
        self::assertCredentialJsonLength($credentialJson);
        $now ??= time();
        if ($now < 0) {
            throw new InvalidArgumentException('Passkey verification timestamp must be non-negative.');
        }

        return CacheLock::synchronized(
            $this->cache,
            self::lockKey($binding, $ceremonyId),
            fn (LockProviderInterface $locks, LockHandle $handle): PasskeyResult => $this->finishAuthenticationLocked(
                $binding,
                $ceremonyId,
                $credentialRecordJson,
                $credentialJson,
                $now,
                $locks,
                $handle,
            ),
        );
    }

    public function finishRegistration(
        string $binding,
        string $ceremonyId,
        #[\SensitiveParameter]
        string $credentialJson,
        ?int $now = null,
    ): PasskeyResult {
        self::assertBinding($binding);
        self::assertCeremonyId($ceremonyId);
        self::assertCredentialJsonLength($credentialJson);
        $now ??= time();
        if ($now < 0) {
            throw new InvalidArgumentException('Passkey verification timestamp must be non-negative.');
        }

        return CacheLock::synchronized(
            $this->cache,
            self::lockKey($binding, $ceremonyId),
            fn (LockProviderInterface $locks, LockHandle $handle): PasskeyResult => $this->finishRegistrationLocked(
                $binding,
                $ceremonyId,
                $credentialJson,
                $now,
                $locks,
                $handle,
            ),
        );
    }

    private static function assertBinding(string $binding): void
    {
        if ($binding === '' || strlen($binding) > self::MAX_BINDING_LENGTH) {
            throw new InvalidArgumentException('Passkey bindings must contain between 1 and 190 bytes.');
        }
    }

    private static function assertCeremonyId(string $ceremonyId): void
    {
        try {
            $decoded = sodium_base642bin($ceremonyId, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new InvalidArgumentException('Passkey ceremony ID must be valid URL-safe Base64 without padding.');
        }
        if (strlen($decoded) !== 16) {
            throw new InvalidArgumentException('Passkey ceremony ID must encode exactly 16 bytes.');
        }
    }

    private static function assertCredentialJsonLength(string $json): void
    {
        if ($json === '' || strlen($json) > self::MAX_CREDENTIAL_JSON_LENGTH) {
            throw new InvalidArgumentException('WebAuthn credential JSON must contain between 1 and 131072 bytes.');
        }
    }

    /** @param list<string> $origins */
    private static function assertOrigins(array $origins): void
    {
        if ($origins === [] || count($origins) > 16 || count(array_unique($origins)) !== count($origins)) {
            throw new InvalidArgumentException('Passkey allowed origins must contain 1 to 16 unique origins.');
        }
        foreach ($origins as $origin) {
            self::assertOrigin($origin);
        }
    }

    private static function assertOrigin(string $origin): void
    {
        if ($origin === '' || strlen($origin) > 2048) {
            throw new InvalidArgumentException('Passkey origins must contain between 1 and 2048 bytes.');
        }
        $parts = parse_url($origin);
        if (
            $parts === false
            || !isset($parts['scheme'], $parts['host'])
            || !in_array($parts['scheme'], ['http', 'https'], true)
            || isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
            || (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/')
        ) {
            throw new InvalidArgumentException('Passkey origins must be absolute HTTP(S) origins without paths, credentials, queries, or fragments.');
        }
        if ($parts['scheme'] === 'http' && !in_array($parts['host'], ['localhost', '127.0.0.1', '::1'], true)) {
            throw new InvalidArgumentException('Passkey HTTP origins are allowed only for local development hosts.');
        }
    }

    private static function assertRelyingParty(string $rpId, string $rpName): void
    {
        if (
            $rpId === ''
            || strlen($rpId) > 253
            || preg_match('/\s|:\/\//', $rpId) === 1
            || str_contains($rpId, '/')
        ) {
            throw new InvalidArgumentException('Passkey RP ID must be a host name without a scheme, path, or whitespace.');
        }
        if ($rpName === '' || strlen($rpName) > 255 || preg_match('//u', $rpName) !== 1) {
            throw new InvalidArgumentException('Passkey RP name must be valid UTF-8 between 1 and 255 bytes.');
        }
    }

    private static function assertUserHandle(string $userHandle): void
    {
        if ($userHandle === '' || strlen($userHandle) > 64) {
            throw new InvalidArgumentException('Passkey user handles must contain between 1 and 64 bytes.');
        }
    }

    private static function assertUserName(string $value, string $name): void
    {
        if ($value === '' || strlen($value) > 255 || preg_match('//u', $value) !== 1) {
            throw new InvalidArgumentException($name . ' must be valid UTF-8 between 1 and 255 bytes.');
        }
    }

    private static function encode(string $value): string
    {
        return sodium_bin2base64($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    private static function lockKey(string $binding, string $ceremonyId): string
    {
        return hash('sha256', "infocyph:otp:passkey:lock:v1\0" . $binding . "\0" . $ceremonyId);
    }

    private static function requireDependency(): void
    {
        if (!self::isAvailable()) {
            throw new LogicException(
                'Passkey support requires web-auth/webauthn-lib. Install it with composer require web-auth/webauthn-lib:^5.3.',
            );
        }
    }

    private static function stateKey(string $binding, string $ceremonyId): string
    {
        return hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremonyId);
    }

    /**
     * @param list<string> $recordsJson
     * @return list<\Webauthn\PublicKeyCredentialDescriptor>
     */
    private function credentialDescriptors(array $recordsJson): array
    {
        if (count($recordsJson) > self::MAX_CREDENTIALS) {
            throw new InvalidArgumentException('Passkey ceremonies may include at most 64 credential records.');
        }

        $descriptors = [];
        foreach ($recordsJson as $recordJson) {
            $descriptors[] = $this->deserializeRecord($recordJson)->getPublicKeyCredentialDescriptor();
        }

        return $descriptors;
    }

    private function deleteLocked(string $stateKey, LockProviderInterface $locks, LockHandle $handle): void
    {
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->delete($stateKey)) {
            throw new RuntimeException('Unable to delete passkey ceremony state.');
        }
    }

    private function deserializeCreationOptions(string $json): PublicKeyCredentialCreationOptions
    {
        try {
            $options = $this->serializer->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json');
        } catch (SerializerException|InvalidDataException $failure) {
            throw new RuntimeException('Invalid stored passkey registration options.', previous: $failure);
        }
        if (!$options instanceof PublicKeyCredentialCreationOptions) {
            throw new RuntimeException('Invalid stored passkey registration options.');
        }

        return $options;
    }

    private function deserializeCredential(string $json): ?PublicKeyCredential
    {
        try {
            $credential = $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
        } catch (SerializerException|InvalidDataException) {
            return null;
        }

        return $credential instanceof PublicKeyCredential ? $credential : null;
    }

    private function deserializeRecord(string $json): CredentialRecord
    {
        self::assertCredentialJsonLength($json);
        try {
            $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
        } catch (SerializerException|InvalidDataException $failure) {
            throw new RuntimeException('Invalid persisted passkey credential record.', previous: $failure);
        }
        if (!$record instanceof CredentialRecord) {
            throw new RuntimeException('Invalid persisted passkey credential record.');
        }

        return $record;
    }

    private function deserializeRequestOptions(string $json): PublicKeyCredentialRequestOptions
    {
        try {
            $options = $this->serializer->deserialize($json, PublicKeyCredentialRequestOptions::class, 'json');
        } catch (SerializerException|InvalidDataException $failure) {
            throw new RuntimeException('Invalid stored passkey authentication options.', previous: $failure);
        }
        if (!$options instanceof PublicKeyCredentialRequestOptions) {
            throw new RuntimeException('Invalid stored passkey authentication options.');
        }

        return $options;
    }

    private function finishAuthenticationLocked(
        string $binding,
        string $ceremonyId,
        string $credentialRecordJson,
        string $credentialJson,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): PasskeyResult {
        $stateKey = self::stateKey($binding, $ceremonyId);
        $state = $this->loadActiveState($stateKey, PasskeyCeremony::TYPE_AUTHENTICATION, $now, $locks, $handle);
        if ($state instanceof PasskeyResult) {
            return $state;
        }

        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null || !$credential->response instanceof AuthenticatorAssertionResponse) {
            return PasskeyResult::malformed();
        }
        $record = $this->deserializeRecord($credentialRecordJson);
        if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)) {
            return PasskeyResult::mismatch();
        }
        $expectedUserHandle = $state['userHandle'] ?? $record->userHandle;
        if ($state['userHandle'] !== null && !hash_equals($state['userHandle'], $record->userHandle)) {
            return PasskeyResult::mismatch();
        }

        try {
            $updated = $this->assertionValidator->check(
                $record,
                $credential->response,
                $this->deserializeRequestOptions($state['optionsJson']),
                $this->rpId,
                $expectedUserHandle,
            );
        } catch (AuthenticatorResponseVerificationException) {
            return PasskeyResult::mismatch();
        }

        $this->consumeState($stateKey, $state, $now, $locks, $handle);

        return PasskeyResult::success(
            self::encode($updated->publicKeyCredentialId),
            $this->serializeObject($updated),
            $updated->userHandle === '' ? null : self::encode($updated->userHandle),
        );
    }

    private function finishRegistrationLocked(
        string $binding,
        string $ceremonyId,
        string $credentialJson,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): PasskeyResult {
        $stateKey = self::stateKey($binding, $ceremonyId);
        $state = $this->loadActiveState($stateKey, PasskeyCeremony::TYPE_REGISTRATION, $now, $locks, $handle);
        if ($state instanceof PasskeyResult) {
            return $state;
        }

        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null || !$credential->response instanceof AuthenticatorAttestationResponse) {
            return PasskeyResult::malformed();
        }

        try {
            $record = $this->attestationValidator->check(
                $credential->response,
                $this->deserializeCreationOptions($state['optionsJson']),
                $this->rpId,
            );
        } catch (AuthenticatorResponseVerificationException) {
            return PasskeyResult::mismatch();
        }
        if ($state['userHandle'] === null || !hash_equals($state['userHandle'], $record->userHandle)) {
            throw new RuntimeException('Verified passkey registration returned an unexpected user handle.');
        }

        $this->consumeState($stateKey, $state, $now, $locks, $handle);

        return PasskeyResult::success(
            self::encode($record->publicKeyCredentialId),
            $this->serializeObject($record),
            self::encode($record->userHandle),
        );
    }

    private function issueCeremony(
        string $binding,
        string $type,
        string $optionsJson,
        ?string $userHandle,
        ?int $now,
    ): PasskeyCeremony {
        for ($attempt = 0; $attempt < self::CEREMONY_ATTEMPTS; $attempt++) {
            $ceremonyId = self::encode(random_bytes(16));
            $stateKey = self::stateKey($binding, $ceremonyId);
            $ceremony = CacheLock::synchronized(
                $this->cache,
                self::lockKey($binding, $ceremonyId),
                function (LockProviderInterface $locks, LockHandle $handle) use (
                    $ceremonyId,
                    $optionsJson,
                    $stateKey,
                    $type,
                    $userHandle,
                    $now,
                ): ?PasskeyCeremony {
                    if ($this->cache->get($stateKey) !== null) {
                        return null;
                    }
                    $issuedAt = $now ?? time();
                    if ($issuedAt < 0 || $issuedAt > PHP_INT_MAX - $this->ttlSeconds) {
                        throw new InvalidArgumentException('Passkey ceremony expiration exceeds the supported timestamp range.');
                    }
                    $expiresAt = $issuedAt + $this->ttlSeconds;
                    $state = [
                        'v' => 1,
                        'type' => $type,
                        'optionsJson' => $optionsJson,
                        'userHandle' => $userHandle,
                        'expiresAt' => $expiresAt,
                        'consumed' => false,
                    ];
                    CacheLock::ensureOwned($locks, $handle);
                    if (!$this->cache->set($stateKey, $state, $this->ttlSeconds)) {
                        throw new RuntimeException('Unable to store passkey ceremony state.');
                    }

                    return new PasskeyCeremony($ceremonyId, $type, $optionsJson, $expiresAt);
                },
            );
            if ($ceremony !== null) {
                return $ceremony;
            }
        }

        throw new RuntimeException('Unable to reserve a unique passkey ceremony.');
    }

    /**
     * @return array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool}|PasskeyResult
     */
    private function loadActiveState(
        string $stateKey,
        string $expectedType,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): array|PasskeyResult {
        $stored = $this->cache->get($stateKey);
        if ($stored === null) {
            return PasskeyResult::mismatch();
        }
        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return PasskeyResult::mismatch();
        }
        if ($state['consumed']) {
            return PasskeyResult::replay();
        }
        if ($state['type'] !== $expectedType) {
            return PasskeyResult::mismatch();
        }

        return $state;
    }

    /**
     * @param mixed $state
     * @return array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool}
     */
    private function requireState(mixed $state): array
    {
        if (!is_array($state) || count($state) !== 6) {
            throw new RuntimeException('Invalid passkey ceremony state in CacheLayer.');
        }

        $version = $state['v'] ?? null;
        $type = $state['type'] ?? null;
        $optionsJson = $state['optionsJson'] ?? null;
        $userHandle = $state['userHandle'] ?? null;
        $expiresAt = $state['expiresAt'] ?? null;
        $consumed = $state['consumed'] ?? null;
        if (
            $version !== 1
            || !is_string($type)
            || !in_array($type, [PasskeyCeremony::TYPE_AUTHENTICATION, PasskeyCeremony::TYPE_REGISTRATION], true)
            || !is_string($optionsJson)
            || $optionsJson === ''
            || strlen($optionsJson) > self::MAX_CREDENTIAL_JSON_LENGTH
            || ($userHandle !== null && (!is_string($userHandle) || $userHandle === '' || strlen($userHandle) > 64))
            || !is_int($expiresAt)
            || $expiresAt < 0
            || !is_bool($consumed)
        ) {
            throw new RuntimeException('Invalid passkey ceremony state in CacheLayer.');
        }

        return [
            'v' => $version,
            'type' => $type,
            'optionsJson' => $optionsJson,
            'userHandle' => $userHandle,
            'expiresAt' => $expiresAt,
            'consumed' => $consumed,
        ];
    }

    private function serializeObject(object $value): string
    {
        $json = $this->serializer->serialize($value, 'json');
        if ($json === '' || strlen($json) > self::MAX_CREDENTIAL_JSON_LENGTH) {
            throw new RuntimeException('Serialized WebAuthn payload exceeds the supported size.');
        }

        return $json;
    }

    /** @param array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool} $state */
    private function consumeState(
        string $stateKey,
        array $state,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): void {
        $ttl = $state['expiresAt'] - $now;
        if ($ttl < 1) {
            throw new RuntimeException('Passkey ceremony expired before state consumption.');
        }
        $state['consumed'] = true;
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->set($stateKey, $state, $ttl)) {
            throw new RuntimeException('Unable to consume passkey ceremony state.');
        }
    }
}
