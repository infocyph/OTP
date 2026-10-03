<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Passkey;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\ValueObjects\PasskeyCeremony;
use Infocyph\OTP\VerificationReason;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

$registrationResponse = static function (): string {
    $response = '{"id":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY","type":"public-key","rawId":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB"}}';
    $responseData = json_decode($response, true, 32, JSON_THROW_ON_ERROR);
    $clientData = json_encode([
        'type' => 'webauthn.create',
        'challenge' => 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU',
        'origin' => 'https://webauthn.spomky-labs.com',
        'crossOrigin' => false,
    ], JSON_THROW_ON_ERROR);
    $responseData['response']['clientDataJSON'] = rtrim(strtr(base64_encode($clientData), '+/', '-_'), '=');
    $response = json_encode($responseData, JSON_THROW_ON_ERROR);
    return $response;
};

test('passkey dependency is available in the development matrix', function () {
    expect(Passkey::isAvailable())->toBeTrue();
});

test('passkey registration creates discoverable user-verified options', function () {
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
    $options = json_decode($ceremony->optionsJson, true, 512, JSON_THROW_ON_ERROR);

    expect($ceremony->type)->toBe(PasskeyCeremony::TYPE_REGISTRATION)
        ->and($ceremony->expiresAt)->toBe(1_700_000_300)
        ->and($options['rp']['id'] ?? null)->toBe('example.com')
        ->and($options['user']['name'] ?? null)->toBe('alice@example.com')
        ->and($options['authenticatorSelection']['residentKey'] ?? null)->toBe('required')
        ->and($options['authenticatorSelection']['userVerification'] ?? null)->toBe('required')
        ->and($options['attestation'] ?? null)->toBe('none');

    if (array_key_exists('name', $options['rp'])) {
        expect($options['rp']['name'])->toBe('example.com');
    }
});

test('passkey authentication supports discoverable credentials', function () {
    $service = new Passkey(
        CacheLayerState::memory(),
        'example.com',
        ['https://example.com'],
    );
    $ceremony = $service->beginAuthentication(
        'user-42:passkey:authentication',
        now: 1_700_000_000,
    );
    $options = json_decode($ceremony->optionsJson, true, 512, JSON_THROW_ON_ERROR);

    expect($ceremony->type)->toBe(PasskeyCeremony::TYPE_AUTHENTICATION)
        ->and($options['rpId'] ?? null)->toBe('example.com')
        ->and($options['userVerification'] ?? null)->toBe('required')
        ->and($options['allowCredentials'] ?? null)->toBe([]);
});

test('malformed passkey responses do not consume a ceremony', function () {
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
});

test('embedded malformed WebAuthn JSON and CBOR remain non-consuming malformed results', function () {
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
        $state = $cache->get($stateKey);
        expect($state)->toBeArray()
            ->and($state['consumed'] ?? null)->toBeFalse();
    }
});

test('consumed passkey ceremony state reports replay before parsing another response', function () {
    $cache = CacheLayerState::memory();
    $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 60);
    $ceremony = $service->beginRegistration('binding', 'user-handle', 'alice', 'Alice', now: 100);
    $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0binding\0" . $ceremony->id);
    $state = $cache->get($stateKey);
    expect($state)->toBeArray();
    $state['consumed'] = true;
    $cache->set($stateKey, $state, 60);

    $result = $service->finishRegistration('binding', $ceremony->id, '{}', 101);

    expect($result->matched)->toBeFalse()
        ->and($result->reason)->toBe(VerificationReason::Replay)
        ->and($result->replayDetected)->toBeTrue();
});

test('expired passkey ceremony is rejected and deleted', function () {
    $cache = CacheLayerState::memory();
    $service = new Passkey($cache, 'example.com', ['https://example.com'], ttlSeconds: 10);
    $ceremony = $service->beginRegistration('binding', 'user-handle', 'alice', 'Alice', now: 100);
    $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0binding\0" . $ceremony->id);

    $result = $service->finishRegistration('binding', $ceremony->id, '{}', 111);

    expect($result->reason)->toBe(VerificationReason::Mismatch)
        ->and($cache->get($stateKey))->toBeNull();
});

test('passkey configuration rejects unsafe relying party input', function () {
    $cache = CacheLayerState::memory();

    expect(fn () => new Passkey($cache, 'https://example.com', ['https://example.com']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Passkey($cache, 'example.com', ['http://example.com']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Passkey($cache, 'example.com', ['https://example.com/']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Passkey($cache, 'example.com', []))
        ->toThrow(InvalidArgumentException::class);
});


test('malformed WebAuthn payload corpus remains a non-consuming credential failure', function () {
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
        $state = $cache->get($stateKey);
        expect($state)->toBeArray()
            ->and($state['consumed'] ?? null)->toBeFalse();
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
});

test('valid WebAuthn registration fixture succeeds once and then reports replay', function () use ($registrationResponse) {
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
    $state = $cache->get($stateKey);
    expect($state)->toBeArray();
    $options = json_decode($state['optionsJson'], true, 32, JSON_THROW_ON_ERROR);
    $options['challenge'] = 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU';
    $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);
    expect($cache->set($stateKey, $state, 60))->toBeTrue();

    $response = $registrationResponse();
    $first = $service->finishRegistration($binding, $ceremony->id, $response, 101);
    $second = $service->finishRegistration($binding, $ceremony->id, $response, 102);

    expect($first->matched)->toBeTrue()
        ->and($first->credentialId)->not->toBeNull()
        ->and($first->credentialRecordJson)->not->toBeNull()
        ->and($second->reason)->toBe(VerificationReason::Replay)
        ->and($second->replayDetected)->toBeTrue();
});

test('expired atomic passkey ceremony remains terminal for a stale valid registration', function () use ($registrationResponse) {
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

            $state = $value;

            return true;
        },
    );
    $atomic->method('compareAndSet')->willReturnCallback(
        function (string $key, mixed $expected, mixed $replacement, mixed $ttl) use (&$state): bool {
            unset($key, $ttl);
            if ($state !== $expected) {
                return false;
            }

            $state = $replacement;

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

    expect($state)->toBeArray();
    $options = json_decode($state['optionsJson'], true, 32, JSON_THROW_ON_ERROR);
    $options['challenge'] = 'XKADkZSW9B4h0Fek8KbhQun3m4dfJYN3ci9wdXDNJvU';
    $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);

    $expired = $service->finishRegistration($binding, $ceremony->id, '{}', 111);
    $stale = $service->finishRegistration($binding, $ceremony->id, $registrationResponse(), 101);

    expect($expired->reason)->toBe(VerificationReason::Mismatch)
        ->and($state)->toBeArray()
        ->and($state['consumed'] ?? null)->toBeTrue()
        ->and($stale->matched)->toBeFalse()
        ->and($stale->reason)->toBe(VerificationReason::Replay)
        ->and($stale->replayDetected)->toBeTrue();
});

test('valid WebAuthn assertion fixture succeeds once and advances the credential counter', function () {
    $cache = CacheLayerState::memory();
    $service = new Passkey(
        $cache,
        'spomky-webauthn.herokuapp.com',
        ['https://spomky-webauthn.herokuapp.com'],
        ttlSeconds: 60,
    );
    $userHandle = 'abfc8fdf-07f6-45a9-abec-fa192275b276';
    $credentialId = base64_decode(
        'ADqYfFWXiscOCOPCd9OLiBtSGhletNPKlSOELS0Nuwj/uCzf9s3trLUK9ockO8xa8jBAYdKixLZYOAezy0FJiV1bnTCty/LiInWWJlov',
        true,
    );
    $publicKey = base64_decode(
        'pQECAyYgASFYIAilQMlKgtJyC4tEMoERzfa/rzaLpE+PLpIVmcVMGPZBIlggbwNLQKmmGPIXJkH3HIJOsoOyv9LmJfmGGJ1YtF0//sE=',
        true,
    );
    if (!is_string($credentialId) || !is_string($publicKey)) {
        throw new RuntimeException('Invalid embedded WebAuthn assertion fixture.');
    }

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
    $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremony->id);
    $state = $cache->get($stateKey);
    expect($state)->toBeArray();
    $options = json_decode($state['optionsJson'], true, 32, JSON_THROW_ON_ERROR);
    $options['challenge'] = 'wKlW7S3EENHlcF2NgYhdUJfRJeCvAvlbk-Mllvxo0HA';
    $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);
    expect($cache->set($stateKey, $state, 60))->toBeTrue();

    $response = '{"id":"ADqYfFWXiscOCOPCd9OLiBtSGhletNPKlSOELS0Nuwj_uCzf9s3trLUK9ockO8xa8jBAYdKixLZYOAezy0FJiV1bnTCty_LiInWWJlov","type":"public-key","rawId":"ADqYfFWXiscOCOPCd9OLiBtSGhletNPKlSOELS0Nuwj/uCzf9s3trLUK9ockO8xa8jBAYdKixLZYOAezy0FJiV1bnTCty/LiInWWJlov","response":{"authenticatorData":"tIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXFBJyQAAAAAAAAAAAAAAAAAAAAAATgA6mHxVl4rHDgjjwnfTi4gbUhoZXrTTypUjhC0tDbsI_7gs3_bN7ay1CvaHJDvMWvIwQGHSosS2WDgHs8tBSYldW50wrcvy4iJ1liZaL6UBAgMmIAEhWCAIpUDJSoLScguLRDKBEc32v682i6RPjy6SFZnFTBj2QSJYIG8DS0CpphjyFyZB9xyCTrKDsr_S5iX5hhidWLRdP_7B","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ3S2xXN1MzRUVOSGxjRjJOZ1loZFVKZlJKZUN2QXZsYmstTWxsdnhvMEhBIiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEQCIBnVPX8inAXIxXAsMdF6nW6nZJa36G1O+G9JXiauenxBAiBU4MQoRWxiXGn0TcKTkRJafZ58KLqeCJiB2VFAplwPJA==","userHandle":"YWJmYzhmZGYtMDdmNi00NWE5LWFiZWMtZmExOTIyNzViMjc2"}}';
    $first = $service->finishAuthentication($binding, $ceremony->id, $recordJson, $response, 101);
    $second = $service->finishAuthentication($binding, $ceremony->id, $recordJson, $response, 102);

    expect($first->matched)->toBeTrue()
        ->and($first->credentialRecordJson)->not->toBeNull()
        ->and($second->reason)->toBe(VerificationReason::Replay)
        ->and($second->replayDetected)->toBeTrue();

    $updated = $serializer->deserialize(
        $first->credentialRecordJson ?? throw new RuntimeException('Missing verified credential record.'),
        CredentialRecord::class,
        'json',
    );
    expect($updated)->toBeInstanceOf(CredentialRecord::class)
        ->and($updated->counter)->toBe(1_548_765_641);
});
