<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Passkey;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\ValueObjects\PasskeyCeremony;
use Infocyph\OTP\VerificationReason;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @return array<array-key, mixed>
 * @throws \RuntimeException
 */
function passkeyFixtureArray(mixed $value): array
{
    if (!is_array($value)) {
        throw new RuntimeException('Expected a passkey fixture array.');
    }

    return $value;
}

/**
 * @throws \RuntimeException
 */
function passkeyFixtureString(mixed $value): string
{
    if (!is_string($value)) {
        throw new RuntimeException('Expected a passkey fixture string.');
    }

    return $value;
}

/**
 * @throws \RuntimeException
 */
function passkeyRegistrationResponse(): string
{
    $response = '{"id":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY","type":"public-key","rawId":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB"}}';
    $responseData = passkeyFixtureArray(json_decode($response, true, 32, JSON_THROW_ON_ERROR));
    $responseData['response'] = passkeyFixtureArray($responseData['response'] ?? null);
    $clientData = json_encode([
        'type' => 'webauthn.create',
        'challenge' => 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU',
        'origin' => 'https://webauthn.spomky-labs.com',
        'crossOrigin' => false,
    ], JSON_THROW_ON_ERROR);
    $responseData['response']['clientDataJSON'] = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');
    $response = json_encode($responseData, JSON_THROW_ON_ERROR);
    return $response;
}

final class PasskeyTest extends TestCase
{
    /** @return list<array{string}> */
    public static function nativePdoBackends(): array
    {
        return [['MYSQL'], ['MARIADB'], ['POSTGRES']];
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[DataProvider('nativePdoBackends')]
    #[TestDox('native PDO passkey registration permits exactly one completion for $backend')]
    public function testNativePdoRegistrationRace(string $backend): void
    {
        $factory = CacheLayerState::pdoFactory($backend);
        $cache = $factory();
        $binding = 'fixture-native-registration';
        $rp = 'webauthn.spomky-labs.com';
        $origins = ['https://webauthn.spomky-labs.com'];

        try {
            $service = new Passkey($cache, $rp, $origins, ttlSeconds: 60);
            $ceremony = $service->beginRegistration(
                $binding,
                'f6eabc4b-b92b-4c24-867c-efcba88cc94f',
                'test@example.com',
                'Test User',
                now: 100,
            );
            $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremony->id);
            $independent = $factory();
            $state = passkeyFixtureArray($independent->get($stateKey));
            $options = passkeyFixtureArray(json_decode(passkeyFixtureString($state['optionsJson'] ?? null), true, 32, JSON_THROW_ON_ERROR));
            $options['challenge'] = 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU';
            $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);
            expect($independent->set($stateKey, $state, 60))->toBeTrue();

            $response = passkeyRegistrationResponse();
            expect($service->finishRegistration('other-owner', $ceremony->id, $response, 101)->matched)->toBeFalse()
                ->and($independent->get($stateKey))->toBe($state);
            $results = Concurrency::run(
                static fn(): int => (int) new Passkey($factory(), $rp, $origins, ttlSeconds: 60)
                    ->finishRegistration($binding, $ceremony->id, $response, 101)->matched,
                4,
            );
            $consumed = passkeyFixtureArray($independent->get($stateKey));
            $replay = $service->finishRegistration($binding, $ceremony->id, $response, 102);
            expect(array_sum($results))->toBe(1)
                ->and($consumed['consumed'] ?? null)->toBeTrue()
                ->and($consumed['expiresAt'] ?? null)->toBe($state['expiresAt'] ?? null)
                ->and($replay->reason)->toBe(VerificationReason::Replay)
                ->and($replay->replayDetected)->toBeTrue();
        } finally {
            $cache->clear();
        }
    }

    #[TestDox('passkey dependency is available in the development matrix')]
    public function testPasskeyDependencyIsAvailableInTheDevelopmentMatrix(): void
    {
        expect(Passkey::isAvailable())->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('passkey registration creates discoverable user-verified options')]
    public function testPasskeyRegistrationCreatesDiscoverableUserVerifiedOptions(): void
    {
        $service = new Passkey(
            CacheLayerState::memory(),
            'example.com',
            ['https://example.com'],
        );
        $ceremony = $service->beginRegistration(
            'user-42:passkey:registration',
            'user-42',
            'alice@example.com',
            'Alice',
            now: 1_700_000_000,
        );
        $options = passkeyFixtureArray(json_decode($ceremony->optionsJson, true, 512, JSON_THROW_ON_ERROR));
        $rp = passkeyFixtureArray($options['rp'] ?? null);
        $user = passkeyFixtureArray($options['user'] ?? null);
        $selection = passkeyFixtureArray($options['authenticatorSelection'] ?? null);

        expect($ceremony->type)->toBe(PasskeyCeremony::TYPE_REGISTRATION)
            ->and($ceremony->expiresAt)->toBe(1_700_000_300)
            ->and($rp['id'] ?? null)->toBe('example.com')
            ->and($user['name'] ?? null)->toBe('alice@example.com')
            ->and($selection['residentKey'] ?? null)->toBe('required')
            ->and($selection['userVerification'] ?? null)->toBe('required')
            ->and($options['attestation'] ?? null)->toBe('none');

        if (array_key_exists('name', $rp)) {
            expect($rp['name'])->toBe('example.com');
        }
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('passkey authentication supports discoverable credentials')]
    public function testPasskeyAuthenticationSupportsDiscoverableCredentials(): void
    {
        $service = new Passkey(
            CacheLayerState::memory(),
            'example.com',
            ['https://example.com'],
        );
        $ceremony = $service->beginAuthentication(
            'user-42:passkey:authentication',
            now: 1_700_000_000,
        );
        $options = passkeyFixtureArray(json_decode($ceremony->optionsJson, true, 512, JSON_THROW_ON_ERROR));

        expect($ceremony->type)->toBe(PasskeyCeremony::TYPE_AUTHENTICATION)
            ->and($options['rpId'] ?? null)->toBe('example.com')
            ->and($options['userVerification'] ?? null)->toBe('required')
            ->and($options['allowCredentials'] ?? null)->toBe([]);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('malformed passkey responses do not consume a ceremony')]
    public function testMalformedPasskeyResponsesDoNotConsumeACeremony(): void
    {
        $service = new Passkey(
            CacheLayerState::memory(),
            'example.com',
            ['https://example.com'],
            ttlSeconds: 60,
        );
        $ceremony = $service->beginRegistration(
            'binding',
            'user-handle',
            'alice@example.com',
            'Alice',
            now: 100,
        );

        $first = $service->finishRegistration('binding', $ceremony->id, '{}', 101);
        $second = $service->finishRegistration('binding', $ceremony->id, '{}', 102);

        expect($first->reason)->toBe(VerificationReason::Malformed)
            ->and($second->reason)->toBe(VerificationReason::Malformed)
            ->and(fn () => $service->extractCredentialId('{}'))
            ->toThrow(InvalidArgumentException::class);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('embedded malformed WebAuthn JSON and CBOR remain non-consuming malformed results')]
    public function testEmbeddedMalformedWebAuthnJSONAndCBORRemainNonConsumingMalformedResults(): void
    {
        $cache = CacheLayerState::memory();
        $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 60);
        $ceremony = $service->beginRegistration(
            'embedded-malformed',
            'user-handle',
            'alice@example.com',
            'Alice',
            now: 100,
        );
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0embedded-malformed\0" . $ceremony->id);
        $validAttestationObject = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB';
        $payloads = [
            json_encode([
                'id' => 'YQ',
                'rawId' => 'YQ',
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => 'bm90LWpzb24',
                    'attestationObject' => $validAttestationObject,
                ],
            ], JSON_THROW_ON_ERROR),
            json_encode([
                'id' => 'YQ',
                'rawId' => 'YQ',
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoieCIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ',
                    'attestationObject' => 'YQ',
                ],
            ], JSON_THROW_ON_ERROR),
        ];

        foreach ($payloads as $payload) {
            $result = $service->finishRegistration(
                'embedded-malformed',
                $ceremony->id,
                $payload,
                101,
            );

            expect($result->reason)->toBe(VerificationReason::Malformed);
            $state = passkeyFixtureArray($cache->get($stateKey));
            expect($state['consumed'] ?? null)->toBeFalse();
        }
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('consumed passkey ceremony state reports replay before parsing another response')]
    public function testConsumedPasskeyCeremonyStateReportsReplayBeforeParsingAnotherResponse(): void
    {
        $cache = CacheLayerState::memory();
        $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 60);
        $ceremony = $service->beginRegistration('binding', 'user-handle', 'alice', 'Alice', now: 100);
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0binding\0" . $ceremony->id);
        $state = passkeyFixtureArray($cache->get($stateKey));
        $state['consumed'] = true;
        $cache->set($stateKey, $state, 60);

        $result = $service->finishRegistration('binding', $ceremony->id, '{}', 101);

        expect($result->matched)->toBeFalse()
            ->and($result->reason)->toBe(VerificationReason::Replay)
            ->and($result->replayDetected)->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('expired passkey ceremony is rejected and deleted')]
    public function testExpiredPasskeyCeremonyIsRejectedAndDeleted(): void
    {
        $cache = CacheLayerState::memory();
        $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 10);
        $ceremony = $service->beginRegistration('binding', 'user-handle', 'alice', 'Alice', now: 100);
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0binding\0" . $ceremony->id);

        $result = $service->finishRegistration('binding', $ceremony->id, '{}', 111);

        expect($result->reason)->toBe(VerificationReason::Mismatch)
            ->and($cache->get($stateKey))->toBeNull();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('Passkey checks implicit ceremony expiry after delayed state access')]
    public function testPasskeyRechecksImplicitClockAfterStateAccess(): void
    {
        $ceremonyId = rtrim(strtr(base64_encode(str_repeat('a', 16)), '+/', '-_'), '=');
        foreach ([PasskeyCeremony::TYPE_REGISTRATION, PasskeyCeremony::TYPE_AUTHENTICATION] as $type) {
            $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
            $cache->expects($this->once())->method('get')->willReturnCallback(static function () use ($type): array {
                $expiresAt = time() + 1;
                usleep(1_100_000);

                return [
                    'v' => 1,
                    'type' => $type,
                    'optionsJson' => '{}',
                    'userHandle' => 'user-handle',
                    'expiresAt' => $expiresAt,
                    'consumed' => false,
                ];
            });
            $cache->expects($this->once())->method('delete')->willReturn(true);
            $cache->expects($this->never())->method('set');

            $service = new Passkey($cache, 'example.com', ['https://example.com']);
            $result = $type === PasskeyCeremony::TYPE_REGISTRATION
                ? $service->finishRegistration('binding', $ceremonyId, '{}')
                : $service->finishAuthentication('binding', $ceremonyId, '{}', '{}');
            expect($result->reason)->toBe(VerificationReason::Mismatch);
        }
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('passkey configuration rejects unsafe relying party input')]
    public function testPasskeyConfigurationRejectsUnsafeRelyingPartyInput(): void
    {
        $cache = CacheLayerState::memory();

        expect(fn () => new Passkey($cache, 'https://example.com', ['https://example.com']))
            ->toThrow(InvalidArgumentException::class)
            ->and(fn () => new Passkey($cache, 'example.com', ['http://example.com']))
            ->toThrow(InvalidArgumentException::class)
            ->and(fn () => new Passkey($cache, 'example.com', ['https://example.com/']))
            ->toThrow(InvalidArgumentException::class)
            ->and(fn () => new Passkey($cache, 'example.com', []))
            ->toThrow(InvalidArgumentException::class);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('malformed WebAuthn payload corpus remains a non-consuming credential failure')]
    public function testMalformedWebAuthnPayloadCorpusRemainsANonConsumingCredentialFailure(): void
    {
        $cache = CacheLayerState::memory();
        $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 60);
        $ceremony = $service->beginRegistration(
            'malformed-binding',
            'malformed-user',
            'alice@example.com',
            'Alice',
            now: 100,
        );
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0malformed-binding\0" . $ceremony->id);
        $malformed = [
            'null',
            '42',
            '"scalar"',
            '[]',
            '{"id":"a","rawId":"a","type":"public-key","response":[]}',
            '{"id":1,"rawId":"a","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}',
            '{"id":"a","rawId":1,"type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}',
            '{"id":"a","rawId":"a","type":"wrong","response":{"clientDataJSON":"e30","attestationObject":"e30"}}',
            '{"id":"a","rawId":"a","type":"public-key","response":{"clientDataJSON":1,"attestationObject":"e30"}}',
            '{"id":"!","rawId":"!","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}',
            '{"id":"YQ","rawId":"Yg","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}',
            '{"id":"YQ","rawId":"YQ","type":"public-key","response":{"clientDataJSON":"!","attestationObject":"!"}}',
        ];

        foreach ($malformed as $payload) {
            $result = $service->finishRegistration('malformed-binding', $ceremony->id, $payload, 101);

            expect($result->reason)->toBe(VerificationReason::Malformed);
            $state = passkeyFixtureArray($cache->get($stateKey));
            expect($state['consumed'] ?? null)->toBeFalse();
        }

        $sentinel = '{"id":"raw-secret-sentinel","rawId":"different-secret-sentinel","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}';
        try {
            $service->extractCredentialId($sentinel);
            $this->fail('Expected malformed credential extraction to fail.');
        } catch (InvalidArgumentException $failure) {
            expect($failure->getMessage())->toBe('Malformed WebAuthn credential payload.')
                ->and($failure->getMessage())->not->toContain('raw-secret-sentinel')
                ->and($failure->getMessage())->not->toContain('different-secret-sentinel');
        }
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('valid WebAuthn registration fixture succeeds once and then reports replay')]
    public function testValidWebAuthnRegistrationFixtureSucceedsOnceAndThenReportsReplay(): void
    {
        $cache = CacheLayerState::memory();
        $service = new Passkey(
            $cache,
            'webauthn.spomky-labs.com',
            ['https://webauthn.spomky-labs.com'],
            ttlSeconds: 60,
        );
        $binding = 'fixture-registration';
        $ceremony = $service->beginRegistration(
            $binding,
            'f6eabc4b-b92b-4c24-867c-efcba88cc94f',
            'test@example.com',
            'Test User',
            now: 100,
        );
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremony->id);
        $state = passkeyFixtureArray($cache->get($stateKey));
        $state = passkeyFixtureArray($state);
        $options = passkeyFixtureArray(json_decode(passkeyFixtureString($state['optionsJson'] ?? null), true, 32, JSON_THROW_ON_ERROR));
        $options['challenge'] = 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU';
        $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);
        expect($cache->set($stateKey, $state, 60))->toBeTrue();

        $response = passkeyRegistrationResponse();
        $first = $service->finishRegistration($binding, $ceremony->id, $response, 101);
        $second = $service->finishRegistration($binding, $ceremony->id, $response, 102);

        expect($first->matched)->toBeTrue()
            ->and($first->credentialId)->not->toBeNull()
            ->and($first->credentialRecordJson)->not->toBeNull()
            ->and($second->reason)->toBe(VerificationReason::Replay)
            ->and($second->replayDetected)->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[TestDox('expired atomic passkey ceremony remains terminal for a stale valid registration')]
    public function testExpiredAtomicPasskeyCeremonyRemainsTerminalForAStaleValidRegistration(): void
    {
        $state = null;

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn(null);
        $cache->method('atomic')->willReturn($atomic);
        $cache->method('get')->willReturnCallback(function (string $key) use (&$state): mixed {
            unset($key);

            return $state;
        });

        $atomic->method('setIfAbsent')->willReturnCallback(
            function (string $key, mixed $value, mixed $ttl) use (&$state): bool {
                unset($key, $ttl);
                if ($state !== null) {
                    return false;
                }

                $state = passkeyFixtureArray($value);

                return true;
            },
        );
        $atomic->method('compareAndSet')->willReturnCallback(
            function (string $key, mixed $expected, mixed $replacement, mixed $ttl) use (&$state): bool {
                unset($key, $ttl);
                if ($state !== $expected) {
                    return false;
                }

                $state = passkeyFixtureArray($replacement);

                return true;
            },
        );

        $service = new Passkey(
            $cache,
            'webauthn.spomky-labs.com',
            ['https://webauthn.spomky-labs.com'],
            ttlSeconds: 10,
        );
        $binding = 'atomic-expiry-registration';
        $ceremony = $service->beginRegistration(
            $binding,
            'f6eabc4b-b92b-4c24-867c-efcba88cc94f',
            'test@example.com',
            'Test User',
            now: 100,
        );

        $state = passkeyFixtureArray($state);
        $options = passkeyFixtureArray(json_decode(passkeyFixtureString($state['optionsJson'] ?? null), true, 32, JSON_THROW_ON_ERROR));
        $options['challenge'] = 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU';
        $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);

        $expired = $service->finishRegistration($binding, $ceremony->id, '{}', 111);
        $stale = $service->finishRegistration($binding, $ceremony->id, passkeyRegistrationResponse(), 101);

        expect($expired->reason)->toBe(VerificationReason::Mismatch)
            ->and(passkeyFixtureArray($state)['consumed'] ?? null)->toBeTrue()
            ->and($stale->matched)->toBeFalse()
            ->and($stale->reason)->toBe(VerificationReason::Replay)
            ->and($stale->replayDetected)->toBeTrue();
    }

    /** @return list<array{string|null}> */
    public static function assertionBackends(): array
    {
        return [[null], ['MYSQL'], ['MARIADB'], ['POSTGRES']];
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Uid\Exception\InvalidArgumentException
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    #[DataProvider('assertionBackends')]
    #[TestDox('valid WebAuthn assertion fixture succeeds once and advances the credential counter')]
    public function testValidWebAuthnAssertionFixtureSucceedsOnceAndAdvancesTheCredentialCounter(?string $backend): void
    {
        $factory = $backend === null ? null : CacheLayerState::pdoFactory($backend);
        $cache = $factory === null ? CacheLayerState::memory() : $factory();

        try {
            $this->assertValidAuthentication($cache, $factory);
        } finally {
            $cache->clear();
        }
    }

    /**
     * @param (\Closure(): \Infocyph\CacheLayer\Cache\Cache)|null $factory
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Uid\Exception\InvalidArgumentException
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    private function assertValidAuthentication(AuthenticationStateCacheInterface $cache, ?\Closure $factory): void
    {
        $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 60);
        $userHandle = 'fixture-user';
        $credentialId = random_bytes(32);
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($privateKey === false) {
            throw new RuntimeException('Unable to create the WebAuthn assertion fixture key.');
        }
        $details = openssl_pkey_get_details($privateKey);
        $ec = passkeyFixtureArray(passkeyFixtureArray($details)['ec'] ?? null);
        $x = $ec['x'] ?? null;
        $y = $ec['y'] ?? null;
        if (!is_string($x) || !is_string($y) || strlen($x) > 32 || strlen($y) > 32) {
            throw new RuntimeException('Invalid P-256 assertion fixture public key.');
        }

        // COSE EC2 key: ES256, P-256 and fixed-width public coordinates.
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
            . str_pad($x, 32, "\0", STR_PAD_LEFT)
            . "\x22\x58\x20"
            . str_pad($y, 32, "\0", STR_PAD_LEFT);
        $record = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            $publicKey,
            $userHandle,
            100,
        );
        $serializer = new WebauthnSerializerFactory(AttestationStatementSupportManager::create())->create();
        $recordJson = $serializer->serialize($record, 'json');

        $binding = 'fixture-authentication';
        $ceremony = $service->beginAuthentication($binding, [$recordJson], $userHandle, now: 100);
        $options = json_decode($ceremony->optionsJson, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($options) || !is_string($options['challenge'] ?? null)) {
            throw new RuntimeException('Missing assertion fixture challenge.');
        }
        $clientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $options['challenge'],
            'origin' => 'https://example.com',
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
        // Assertion authenticator data contains UP/UV and the counter, not attested credential data.
        $authenticatorData = hash('sha256', 'example.com', true) . "\x05" . pack('N', 101);
        if (!openssl_sign($authenticatorData . hash('sha256', $clientData, true), $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign the WebAuthn assertion fixture.');
        }
        $signature = passkeyFixtureString($signature);
        $encode = static fn(string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $response = [
            'id' => $encode($credentialId),
            'type' => 'public-key',
            'rawId' => $encode($credentialId),
            'response' => [
                'authenticatorData' => $encode($authenticatorData),
                'clientDataJSON' => $encode($clientData),
                'signature' => $encode($signature),
                'userHandle' => $encode($userHandle),
            ],
        ];
        $invalid = $response;
        $invalid['response']['signature'] = $encode(str_repeat("\0", strlen($signature)));
        $rejected = $service->finishAuthentication(
            $binding,
            $ceremony->id,
            $recordJson,
            json_encode($invalid, JSON_THROW_ON_ERROR),
            101,
        );
        expect($rejected->matched)->toBeFalse()
            ->and($rejected->reason)->toBe(VerificationReason::Malformed);

        if (!openssl_sign($authenticatorData . hash('sha256', $clientData . "\0", true), $wrongSignature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign the negative WebAuthn assertion fixture.');
        }
        $invalid['response']['signature'] = $encode(passkeyFixtureString($wrongSignature));
        $mismatch = $service->finishAuthentication(
            $binding,
            $ceremony->id,
            $recordJson,
            json_encode($invalid, JSON_THROW_ON_ERROR),
            101,
        );
        expect($mismatch->matched)->toBeFalse()
            ->and($mismatch->reason)->toBe(VerificationReason::Mismatch);

        $json = json_encode($response, JSON_THROW_ON_ERROR);
        if ($factory !== null) {
            $this->assertNativeAuthenticationRace($factory, $ceremony, $binding, $recordJson, $json);

            return;
        }

        $first = $service->finishAuthentication($binding, $ceremony->id, $recordJson, $json, 101);
        $second = $service->finishAuthentication($binding, $ceremony->id, $recordJson, $json, 102);

        expect($first->matched)->toBeTrue()
            ->and($first->credentialRecordJson)->not->toBeNull()
            ->and($second->reason)->toBe(VerificationReason::Replay)
            ->and($second->replayDetected)->toBeTrue();

        $updated = $serializer->deserialize(
            $first->credentialRecordJson ?? throw new RuntimeException('Missing verified credential record.'),
            CredentialRecord::class,
            'json',
        );
        expect($updated->counter)->toBe(101);
    }

    /**
     * @param \Closure(): \Infocyph\CacheLayer\Cache\Cache $factory
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    private function assertNativeAuthenticationRace(
        \Closure $factory,
        PasskeyCeremony $ceremony,
        string $binding,
        string $recordJson,
        string $json,
    ): void {
        $independent = $factory();
        $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremony->id);
        $initial = passkeyFixtureArray($independent->get($stateKey));
        $service = new Passkey($independent, 'example.com', ['https://example.com'], ttlSeconds: 60);
        expect($initial['consumed'] ?? null)->toBeFalse()
            ->and($service->finishAuthentication('other-owner', $ceremony->id, $recordJson, $json, 101)->matched)->toBeFalse()
            ->and($independent->get($stateKey))->toBe($initial);

        $results = Concurrency::run(
            static function () use ($factory, $binding, $ceremony, $recordJson, $json): int {
                $result = new Passkey($factory(), 'example.com', ['https://example.com'], ttlSeconds: 60)
                    ->finishAuthentication($binding, $ceremony->id, $recordJson, $json, 101);
                if (!$result->matched) {
                    if (!$result->replayDetected || $result->reason !== VerificationReason::Replay) {
                        throw new RuntimeException('The losing native assertion must report replay.');
                    }

                    return 0;
                }

                $serializer = new WebauthnSerializerFactory(AttestationStatementSupportManager::create())->create();
                $updated = $serializer->deserialize(
                    $result->credentialRecordJson ?? throw new RuntimeException('Missing verified credential record.'),
                    CredentialRecord::class,
                    'json',
                );
                if ($updated->counter !== 101) {
                    throw new RuntimeException('The winning native assertion did not advance its credential counter.');
                }

                return 1;
            },
            4,
        );
        $consumed = passkeyFixtureArray($independent->get($stateKey));
        $replay = $service->finishAuthentication($binding, $ceremony->id, $recordJson, $json, 102);
        expect(array_sum($results))->toBe(1)
            ->and($consumed['consumed'] ?? null)->toBeTrue()
            ->and($consumed['expiresAt'] ?? null)->toBe($initial['expiresAt'] ?? null)
            ->and($replay->reason)->toBe(VerificationReason::Replay)
            ->and($replay->replayDetected)->toBeTrue();
    }
}
