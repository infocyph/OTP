<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use Infocyph\OTP\Result\PasskeyResult;
use Infocyph\OTP\Support\Base64Url;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\PasskeyCeremony;
use InvalidArgumentException;
use JsonException;
use LogicException;
use RangeException;
use RuntimeException;
use Symfony\Component\Serializer\Exception\ExceptionInterface as SerializerException;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use TypeError;
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

    /** @var positive-int Validated ceremony TTL converted once during construction. */
    private int $timeoutMilliseconds;

    /**
     * @param list<string> $allowedOrigins Exact WebAuthn origins, including scheme and optional port.
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function __construct(
        private AuthenticationStateCacheInterface $cache,
        private string $rpId,
        array $allowedOrigins,
        private int $ttlSeconds = 300,
        bool $allowSubdomains = false,
    ) {
        self::requireDependency();
        self::assertRelyingParty($rpId);
        self::assertOrigins($allowedOrigins);
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('Passkey ceremony TTL must be between 1 and 600 seconds.');
        }
        $this->timeoutMilliseconds = $ttlSeconds * 1000;
        CacheLock::assertSafe($cache);

        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($allowedOrigins, $allowSubdomains);
        $this->assertionValidator = new AuthenticatorAssertionResponseValidator($factory->requestCeremony());
        $this->attestationValidator = new AuthenticatorAttestationResponseValidator($factory->creationCeremony());
        $this->serializer = new WebauthnSerializerFactory(AttestationStatementSupportManager::create())->create();
    }

    /** @return array{cache:string,rpId:string,ttlSeconds:int,assertionValidator:string,attestationValidator:string,serializer:string} */
    public function __debugInfo(): array
    {
        return [
            'cache' => get_debug_type($this->cache),
            'rpId' => $this->rpId,
            'ttlSeconds' => $this->ttlSeconds,
            'assertionValidator' => get_debug_type($this->assertionValidator),
            'attestationValidator' => get_debug_type($this->attestationValidator),
            'serializer' => get_debug_type($this->serializer),
        ];
    }

    public static function isAvailable(): bool
    {
        return class_exists(CeremonyStepManagerFactory::class)
            && class_exists(WebauthnSerializerFactory::class);
    }

    /**
     * @param list<string> $credentialRecordsJson Serialized WebAuthn CredentialRecord values used as allowCredentials.
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    public function beginAuthentication(
        string $binding,
        array $credentialRecordsJson = [],
        #[\SensitiveParameter]
        ?string $userHandle = null,
        ?int $now = null,
        ?RunwireExecutionContext $runwire = null,
    ): PasskeyCeremony {
        self::assertBinding($binding);
        if ($userHandle !== null) {
            self::assertUserHandle($userHandle);
        }
        CacheLock::checkpoint($runwire);
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->rpId,
            allowCredentials: $this->credentialDescriptors($credentialRecordsJson),
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: $this->timeoutMilliseconds,
        );

        return $this->issueCeremony(
            $binding,
            PasskeyCeremony::TYPE_AUTHENTICATION,
            $this->serializeObject($options),
            $userHandle,
            $now,
            $runwire,
        );
    }

    /**
     * @param list<string> $existingCredentialRecordsJson Serialized WebAuthn CredentialRecord values used as excludeCredentials.
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    public function beginRegistration(
        string $binding,
        #[\SensitiveParameter]
        string $userHandle,
        string $username,
        string $displayName,
        array $existingCredentialRecordsJson = [],
        ?int $now = null,
        ?RunwireExecutionContext $runwire = null,
    ): PasskeyCeremony {
        self::assertBinding($binding);
        self::assertUserHandle($userHandle);
        self::assertUserName($username, 'Passkey username');
        self::assertUserName($displayName, 'Passkey display name');
        CacheLock::checkpoint($runwire);
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create(id: $this->rpId),
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
            excludeCredentials: $this->credentialDescriptors($existingCredentialRecordsJson),
            timeout: $this->timeoutMilliseconds,
        );

        return $this->issueCeremony(
            $binding,
            PasskeyCeremony::TYPE_REGISTRATION,
            $this->serializeObject($options),
            $userHandle,
            $now,
            $runwire,
        );
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function extractCredentialId(#[\SensitiveParameter] string $credentialJson): string
    {
        self::assertCredentialJsonLength($credentialJson);
        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null) {
            throw new InvalidArgumentException('Malformed WebAuthn credential payload.');
        }

        return self::encode($credential->rawId);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function finishAuthentication(
        string $binding,
        string $ceremonyId,
        #[\SensitiveParameter]
        string $credentialRecordJson,
        #[\SensitiveParameter]
        string $credentialJson,
        ?int $now = null,
        ?RunwireExecutionContext $runwire = null,
    ): PasskeyResult {
        self::assertBinding($binding);
        self::assertCeremonyId($ceremonyId);
        self::assertCredentialJsonLength($credentialRecordJson);
        self::assertCredentialJsonLength($credentialJson);
        self::assertVerificationTimestamp($now);

        return CacheLock::transition(
            $this->cache,
            self::stateKey($binding, $ceremonyId),
            self::lockKey($binding, $ceremonyId),
            'passkey ceremony',
            fn(mixed $stored): array => $this->finishAuthenticationState(
                $stored,
                $credentialRecordJson,
                $credentialJson,
                $now ?? time(),
            ),
            $runwire,
        );
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function finishRegistration(
        string $binding,
        string $ceremonyId,
        #[\SensitiveParameter]
        string $credentialJson,
        ?int $now = null,
        ?RunwireExecutionContext $runwire = null,
    ): PasskeyResult {
        self::assertBinding($binding);
        self::assertCeremonyId($ceremonyId);
        self::assertCredentialJsonLength($credentialJson);
        self::assertVerificationTimestamp($now);

        return CacheLock::transition(
            $this->cache,
            self::stateKey($binding, $ceremonyId),
            self::lockKey($binding, $ceremonyId),
            'passkey ceremony',
            fn(mixed $stored): array => $this->finishRegistrationState($stored, $credentialJson, $now ?? time()),
            $runwire,
        );
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertBinding(string $binding): void
    {
        self::assertByteLength($binding, self::MAX_BINDING_LENGTH, 'Passkey bindings must contain between 1 and 190 bytes.');
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertByteLength(string $value, int $maximum, string $message): void
    {
        if ($value === '' || strlen($value) > $maximum) {
            throw new InvalidArgumentException($message);
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertCeremonyId(string $ceremonyId): void
    {
        if (strlen(Base64Url::decode($ceremonyId, 'Passkey ceremony ID')) !== 16) {
            throw new InvalidArgumentException('Passkey ceremony ID must encode exactly 16 bytes.');
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertCredentialJsonLength(string $json): void
    {
        self::assertByteLength($json, self::MAX_CREDENTIAL_JSON_LENGTH, 'WebAuthn credential JSON must contain between 1 and 131072 bytes.');
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertOrigin(string $origin): void
    {
        self::assertByteLength($origin, 2048, 'Passkey origins must contain between 1 and 2048 bytes.');

        $scheme = parse_url($origin, PHP_URL_SCHEME);
        $host = parse_url($origin, PHP_URL_HOST);
        $path = parse_url($origin, PHP_URL_PATH);
        $user = parse_url($origin, PHP_URL_USER);
        $pass = parse_url($origin, PHP_URL_PASS);
        $query = parse_url($origin, PHP_URL_QUERY);
        $fragment = parse_url($origin, PHP_URL_FRAGMENT);
        if (
            !is_string($scheme)
            || !is_string($host)
            || !in_array($scheme, ['http', 'https'], true)
            || $user !== null
            || $pass !== null
            || $query !== null
            || $fragment !== null
            || ($path !== null && $path !== '')
        ) {
            throw new InvalidArgumentException('Passkey origins must be exact HTTP(S) origins without paths, credentials, queries, or fragments.');
        }
        if ($scheme === 'http' && !in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            throw new InvalidArgumentException('Passkey HTTP origins are allowed only for local development hosts.');
        }
    }

    /**
     * @param array<array-key, mixed> $origins
     * @throws \InvalidArgumentException
     */
    private static function assertOrigins(array $origins): void
    {
        if (!array_is_list($origins) || $origins === [] || count($origins) > 16) {
            throw new InvalidArgumentException('Passkey allowed origins must be a list containing 1 to 16 unique origins.');
        }
        foreach ($origins as $origin) {
            if (!is_string($origin)) {
                throw new InvalidArgumentException('Passkey allowed origins must contain only strings.');
            }
            self::assertOrigin($origin);
        }
        if (count(array_unique($origins)) !== count($origins)) {
            throw new InvalidArgumentException('Passkey allowed origins must contain 1 to 16 unique origins.');
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertRelyingParty(string $rpId): void
    {
        if (
            $rpId === ''
            || strlen($rpId) > 253
            || preg_match('/\s|:\/\//', $rpId) === 1
            || str_contains($rpId, '/')
        ) {
            throw new InvalidArgumentException('Passkey RP ID must be a host name without a scheme, path, or whitespace.');
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertUserHandle(string $userHandle): void
    {
        self::assertByteLength($userHandle, 64, 'Passkey user handles must contain between 1 and 64 bytes.');
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertUserName(string $value, string $name): void
    {
        $message = $name . ' must be valid UTF-8 between 1 and 255 bytes.';
        self::assertByteLength($value, 255, $message);
        if (preg_match('//u', $value) !== 1) {
            throw new InvalidArgumentException($message);
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertVerificationTimestamp(?int $now): void
    {
        if ((int) $now < 0) {
            throw new InvalidArgumentException('Passkey verification timestamp must be non-negative.');
        }
    }

    private static function encode(string $value): string
    {
        return Base64Url::encode($value);
    }

    private static function hasCredentialPayloadShape(string $json): bool
    {
        try {
            $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }
        if (!is_array($data)) {
            return false;
        }

        $response = $data['response'] ?? null;
        if (
            !is_string($data['id'] ?? null)
            || $data['id'] === ''
            || !is_string($data['rawId'] ?? null)
            || $data['rawId'] === ''
            || ($data['type'] ?? null) !== 'public-key'
            || !is_array($response)
            || !is_string($response['clientDataJSON'] ?? null)
            || $response['clientDataJSON'] === ''
        ) {
            return false;
        }

        return is_string($response['attestationObject'] ?? null)
            || (
                is_string($response['authenticatorData'] ?? null)
                && is_string($response['signature'] ?? null)
            );
    }

    private static function isMalformedCredentialFailure(Throwable $failure): bool
    {
        return $failure instanceof InvalidArgumentException
            || $failure instanceof InvalidDataException
            || $failure instanceof JsonException
            || $failure instanceof RangeException
            || $failure instanceof SerializerException
            || $failure instanceof TypeError;
    }

    private static function lockKey(string $binding, string $ceremonyId): string
    {
        return hash('sha256', "infocyph:otp:passkey:lock:v1\0" . $binding . "\0" . $ceremonyId);
    }

    /**
     * @throws \LogicException
     */
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
     * @param array<array-key, mixed> $recordsJson
     * @return list<\Webauthn\PublicKeyCredentialDescriptor>
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private function credentialDescriptors(array $recordsJson): array
    {
        if (!array_is_list($recordsJson) || count($recordsJson) > self::MAX_CREDENTIALS) {
            throw new InvalidArgumentException('Passkey credential records must be a list containing at most 64 records.');
        }

        $descriptors = [];
        foreach ($recordsJson as $recordJson) {
            if (!is_string($recordJson)) {
                throw new InvalidArgumentException('Passkey credential records must contain only serialized strings.');
            }
            $descriptors[] = $this->deserializeRecord($recordJson)->getPublicKeyCredentialDescriptor();
        }

        return $descriptors;
    }

    /**
     * @throws \RuntimeException
     */
    private function deserializeCreationOptions(string $json): PublicKeyCredentialCreationOptions
    {
        try {
            $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
            if (is_array($data) && is_array($data['rp'] ?? null)) {
                unset($data['rp']['name']);
                $json = json_encode($data, JSON_THROW_ON_ERROR);
            }
        } catch (JsonException $failure) {
            throw new RuntimeException('Invalid stored passkey registration options.', previous: $failure);
        }

        return $this->deserializeStored($json, PublicKeyCredentialCreationOptions::class, 'Invalid stored passkey registration options.');
    }

    /**
     * @throws \Throwable
     */
    private function deserializeCredential(string $json): ?PublicKeyCredential
    {
        if (!self::hasCredentialPayloadShape($json)) {
            return null;
        }

        try {
            $credential = $this->deserializeMixed($json, PublicKeyCredential::class);
        } catch (Throwable $failure) {
            if (self::isMalformedCredentialFailure($failure)) {
                return null;
            }

            throw $failure;
        }

        return $credential instanceof PublicKeyCredential ? $credential : null;
    }

    /**
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     */
    private function deserializeMixed(string $json, string $type): mixed
    {
        return $this->serializer->deserialize($json, $type, 'json');
    }

    /**
     * @throws \RuntimeException
     * @throws \InvalidArgumentException
     */
    private function deserializeRecord(string $json): CredentialRecord
    {
        self::assertCredentialJsonLength($json);

        return $this->deserializeStored($json, CredentialRecord::class, 'Invalid persisted passkey credential record.');
    }

    /**
     * @throws \RuntimeException
     */
    private function deserializeRequestOptions(string $json): PublicKeyCredentialRequestOptions
    {
        return $this->deserializeStored($json, PublicKeyCredentialRequestOptions::class, 'Invalid stored passkey authentication options.');
    }

    /**
     * @template T of object
     * @param class-string<T> $type
     * @return T
     * @throws \RuntimeException
     */
    private function deserializeStored(string $json, string $type, string $message): object
    {
        try {
            $value = $this->deserializeMixed($json, $type);
        } catch (SerializerException $failure) {
            throw new RuntimeException($message, previous: $failure);
        }
        if (!$value instanceof $type) {
            throw new RuntimeException($message);
        }

        return $value;
    }

    /**
     * @return array{
     *     result:PasskeyResult,
     *     replacement?:array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool},
     *     ttl?:int,
     *     delete?:bool,
     *     failure?:string
     * }
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function finishAuthenticationState(
        mixed $stored,
        string $credentialRecordJson,
        string $credentialJson,
        int $now,
    ): array {
        $decision = $this->loadStateDecision($stored, PasskeyCeremony::TYPE_AUTHENTICATION, $now);
        if ($decision['transition'] !== null) {
            return $decision['transition'];
        }
        $state = $decision['state'] ?? throw new LogicException('Missing verified passkey state.');

        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null || !($credential->response instanceof AuthenticatorAssertionResponse)) {
            return ['result' => PasskeyResult::malformed()];
        }
        $record = $this->deserializeRecord($credentialRecordJson);
        if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)) {
            return ['result' => PasskeyResult::mismatch()];
        }
        if ($state['userHandle'] !== null && !hash_equals($state['userHandle'], $record->userHandle)) {
            return ['result' => PasskeyResult::mismatch()];
        }
        $expectedUserHandle = $state['userHandle'] ?? $record->userHandle;

        $options = $this->deserializeRequestOptions($state['optionsJson']);

        try {
            $updated = $this->assertionValidator->check(
                $record,
                $credential->response,
                $options,
                $this->rpId,
                $expectedUserHandle,
            );
        } catch (AuthenticatorResponseVerificationException) {
            return ['result' => PasskeyResult::mismatch()];
        } catch (InvalidArgumentException) {
            // COSE signature decoding can reject malformed authenticator input before verification.
            return ['result' => PasskeyResult::malformed()];
        }

        $state['consumed'] = true;

        return [
            'result' => PasskeyResult::success(
                self::encode($updated->publicKeyCredentialId),
                $this->serializeObject($updated),
                $updated->userHandle === '' ? null : self::encode($updated->userHandle),
            ),
            'replacement' => $state,
            'ttl' => $state['expiresAt'] - $now,
            'failure' => 'Unable to consume passkey ceremony state.',
        ];
    }

    /**
     * @return array{
     *     result:PasskeyResult,
     *     replacement?:array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool},
     *     ttl?:int,
     *     delete?:bool,
     *     failure?:string
     * }
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function finishRegistrationState(mixed $stored, string $credentialJson, int $now): array
    {
        $decision = $this->loadStateDecision($stored, PasskeyCeremony::TYPE_REGISTRATION, $now);
        if ($decision['transition'] !== null) {
            return $decision['transition'];
        }
        $state = $decision['state'] ?? throw new LogicException('Missing verified passkey state.');

        $credential = $this->deserializeCredential($credentialJson);
        if ($credential === null || !($credential->response instanceof AuthenticatorAttestationResponse)) {
            return ['result' => PasskeyResult::malformed()];
        }

        try {
            $record = $this->attestationValidator->check(
                $credential->response,
                $this->deserializeCreationOptions($state['optionsJson']),
                $this->rpId,
            );
        } catch (AuthenticatorResponseVerificationException) {
            return ['result' => PasskeyResult::mismatch()];
        }
        if ($state['userHandle'] === null || !hash_equals($state['userHandle'], $record->userHandle)) {
            throw new RuntimeException('Verified passkey registration returned an unexpected user handle.');
        }

        $state['consumed'] = true;

        return [
            'result' => PasskeyResult::success(
                self::encode($record->publicKeyCredentialId),
                $this->serializeObject($record),
                self::encode($record->userHandle),
            ),
            'replacement' => $state,
            'ttl' => $state['expiresAt'] - $now,
            'failure' => 'Unable to consume passkey ceremony state.',
        ];
    }

    /**
     * @throws \RuntimeException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    private function issueCeremony(
        string $binding,
        string $type,
        string $optionsJson,
        ?string $userHandle,
        ?int $now,
        ?RunwireExecutionContext $runwire,
    ): PasskeyCeremony {
        for ($attempt = 0; $attempt < self::CEREMONY_ATTEMPTS; $attempt++) {
            $ceremonyId = self::encode(random_bytes(16));
            $ceremony = CacheLock::transition(
                $this->cache,
                self::stateKey($binding, $ceremonyId),
                self::lockKey($binding, $ceremonyId),
                'passkey ceremony',
                fn(mixed $stored): array => $this->issueState(
                    $stored,
                    $ceremonyId,
                    $type,
                    $optionsJson,
                    $userHandle,
                    $now,
                ),
                $runwire,
            );
            if ($ceremony !== null) {
                return $ceremony;
            }
        }

        throw new RuntimeException('Unable to reserve a unique passkey ceremony.');
    }

    /**
     * @return array{
     *     result:PasskeyCeremony|null,
     *     replacement?:array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool},
     *     ttl?:int,
     *     failure?:string
     * }
     * @throws \InvalidArgumentException
     */
    private function issueState(
        mixed $stored,
        string $ceremonyId,
        string $type,
        string $optionsJson,
        ?string $userHandle,
        ?int $now,
    ): array {
        if ($stored !== null) {
            return ['result' => null];
        }
        $issuedAt = $now ?? time();
        if ($issuedAt < 0 || $issuedAt > PHP_INT_MAX - $this->ttlSeconds) {
            throw new InvalidArgumentException('Passkey ceremony expiration exceeds the supported timestamp range.');
        }
        $expiresAt = $issuedAt + $this->ttlSeconds;

        return [
            'result' => new PasskeyCeremony($ceremonyId, $type, $optionsJson, $expiresAt),
            'replacement' => [
                'v' => 1,
                'type' => $type,
                'optionsJson' => $optionsJson,
                'userHandle' => $userHandle,
                'expiresAt' => $expiresAt,
                'consumed' => false,
            ],
            'ttl' => $this->ttlSeconds,
            'failure' => 'Unable to store passkey ceremony state.',
        ];
    }

    /**
     * @return array{
     *     state:array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool}|null,
     *     transition:array{result:PasskeyResult,replacement?:array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool},ttl?:int,delete?:bool,failure?:string}|null
     * }
     * @throws \RuntimeException
     * @throws \InvalidArgumentException
     */
    private function loadStateDecision(mixed $stored, string $expectedType, int $now): array
    {
        if ($stored === null) {
            return ['state' => null, 'transition' => ['result' => PasskeyResult::mismatch()]];
        }
        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now) {
            $state['consumed'] = true;
            $state['expiresAt'] = $now;

            return [
                'state' => null,
                'transition' => [
                    'result' => PasskeyResult::mismatch(),
                    'replacement' => $state,
                    'ttl' => 1,
                    'delete' => true,
                    'failure' => 'Unable to delete passkey ceremony state.',
                ],
            ];
        }
        if ($state['consumed']) {
            return ['state' => null, 'transition' => ['result' => PasskeyResult::replay()]];
        }
        if ($state['type'] !== $expectedType) {
            return ['state' => null, 'transition' => ['result' => PasskeyResult::mismatch()]];
        }

        return ['state' => $state, 'transition' => null];
    }

    /**
     * @return array{v:int,type:string,optionsJson:string,userHandle:?string,expiresAt:int,consumed:bool}
     * @throws \RuntimeException
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

    /**
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     */
    private function serializeObject(object $value): string
    {
        $json = $this->serializer->serialize($value, 'json');
        if ($json === '' || strlen($json) > self::MAX_CREDENTIAL_JSON_LENGTH) {
            throw new RuntimeException('Serialized WebAuthn payload exceeds the supported size.');
        }

        return $json;
    }
}
