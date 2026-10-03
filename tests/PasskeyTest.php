<?php

declare(strict_types=1);

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
        ->and($options['rp']['name'] ?? null)->toBe('')
        ->and($options['user']['name'] ?? null)->toBe('alice@example.com')
        ->and($options['authenticatorSelection']['residentKey'] ?? null)->toBe('required')
        ->and($options['authenticatorSelection']['userVerification'] ?? null)->toBe('required')
        ->and($options['attestation'] ?? null)->toBe('none');
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

test('valid WebAuthn registration fixture succeeds once and then reports replay', function () {
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

    $response = '{"id":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY","type":"public-key","rawId":"WsVEgVplFhLkRd68yW3KAIyVJ90ZsQOHFjnL71YirSY=","response":{"clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlhLQURrWlNXOUI0aDBGZWs4S2JoUXVuM200ZGZKWU4zY2k5d2RYRE5KdlUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ5YE6oKCTpikraFLRGLQ1zqOxGkTDakbGTB0WSKfdKNZRQAAAABgKLAXsdRMArSzr82vyWuyACBaxUSBWmUWEuRF3rzJbcoAjJUn3RmxA4cWOcvvViKtJqQBAwM5AQAgWQEAv5VUWjpRGBvp2zawiX2JKC9WSDvVxlLfqNqU1EYsdN6iNg16FFF/0EHkt7tJz9wkwC3Cx5vYFyblUw7UF5m8qS579OcGRjvb6MHj+MQFuOKCoowBMY/VjuF+TT14deKMuWtShT2MCab1gtfnkuGAlEcu2CASvAwtbEPKZ2JkaouWWaJ3hDOYTXWYgCgtM5DqqnN9JUZjXrgmAfQC82SYh6ZAV+MQ2s4RG2jP/dvEt235oFSIkr3JEqhStQvJ+CFmjVk67oFtofcISax44CynCd2Lr89inWU1B0JwSB1oyuLPq5HCQuSmFed/piGjVfFgCbN0tCXJkAGufkDXE3J4xSFDAQAB"}}';
    $first = $service->finishRegistration($binding, $ceremony->id, $response, 101);
    $second = $service->finishRegistration($binding, $ceremony->id, $response, 102);

    expect($first->matched)->toBeTrue()
        ->and($first->credentialId)->not->toBeNull()
        ->and($first->credentialRecordJson)->not->toBeNull()
        ->and($second->reason)->toBe(VerificationReason::Replay)
        ->and($second->replayDetected)->toBeTrue();
});

test('valid WebAuthn assertion fixture succeeds once and advances the credential counter', function () {
    $cache = CacheLayerState::memory();
    $service = new Passkey(
        $cache,
        'webauthn.spomky-labs.com',
        ['https://webauthn.spomky-labs.com'],
        ttlSeconds: 60,
    );
    $userHandle = 'ee13d4f1-4863-47dd-a407-097cb49ac822';
    $credentialId = base64_decode('6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=', true);
    $publicKey = base64_decode(
        'pAEDAzkBACBZAQDwn2Ee7V+9GNDn2iCU2plQnIVmZG/vOiXSHb9TQzC5806bGzLV918+1SLFhMhlX5jua2rdXt65nYw9Eln7mbmVxLBDmEm2wod6wP2HinC9HPsYwr75tMRakLMNFfH4Xx4lEsjulRmv68yl/N8XH64X8LKe2GBxjqcuJR+c3LbW4D5dWt/1pGL8fS1UbO3abA/d3IeEsP8RpEz5eVo6qBhb4r0VTo2NMeq75saBHIj4whqo6qsRqRvBmK2d9NAecBFFRIQ31NUtEQZPqXOzkbXGehDi7c3YJPBkTW9kMqcosob9Vlru+vVab+1PnFRdqaklR1UtmhrWte/wB61Hm3xdIUMBAAE=',
        true,
    );
    expect($credentialId)->toBeString()
        ->and($publicKey)->toBeString();

    $record = CredentialRecord::create(
        $credentialId,
        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
        [],
        'none',
        EmptyTrustPath::create(),
        Uuid::fromBinary(base64_decode('YCiwF7HUTAK0s6/Nr8lrsg==', true)),
        $publicKey,
        $userHandle,
        0,
    );
    $serializer = new WebauthnSerializerFactory(AttestationStatementSupportManager::create())->create();
    $recordJson = $serializer->serialize($record, 'json');

    $binding = 'fixture-authentication';
    $ceremony = $service->beginAuthentication($binding, [$recordJson], $userHandle, now: 100);
    $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0" . $binding . "\0" . $ceremony->id);
    $state = $cache->get($stateKey);
    expect($state)->toBeArray();
    $options = json_decode($state['optionsJson'], true, 32, JSON_THROW_ON_ERROR);
    $options['challenge'] = 'w-BeaUTZZnYMzvUB5GWUpiT1WYOnr9iCGUt5irUiUko';
    $state['optionsJson'] = json_encode($options, JSON_THROW_ON_ERROR);
    expect($cache->set($stateKey, $state, 60))->toBeTrue();

    $response = '{"id":"6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x-18","type":"public-key","rawId":"6oRgydKXdC3LtZBDoAXxKnWte68elEQejDrYOV9x+18=","response":{"authenticatorData":"lgTqgoJOmKStoUtEYtDXOo7EaRMNqRsZMHRZIp90o1kFAAAABA","clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogInctQmVhVVRaWm5ZTXp2VUI1R1dVcGlUMVdZT25yOWlDR1V0NWlyVWlVa28iLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4uc3BvbWt5LWxhYnMuY29tIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0","signature":"lV7pKH+0rVaaWC5ZoQIMSW1EjeIELfUTKcplaSW65I8rH7U38qVoTYyvxQiZwtQsqKgXOMQYJ6n1JV+is3yi8wOjxkkmR/bLPPssLz7Za1ooSAJ+R1JKTYsmsozpTmouCVtBN4Il92Zrhy9sOD3pVUjHUJaXaEsV2dReqEamwt9+VLQiD0fJwYrqiyWETEybGqJSj7p2Zb0BVOcevlPCj3tX84DreZMW7lkYE6PyuJCmi7eR/kKq2N+ohvH6H3aHloQ+kgSb2L2gJn1hjs5Z3JxMvrwmnj0Vx1J2AMWrQyuBeBblJN3UP3Wbk16e+8Bq8HC9W6JG9qgqTyR1wJx0Yw==","userHandle":"ZWUxM2Q0ZjEtNDg2My00N2RkLWE0MDctMDk3Y2I0OWFjODIy"}}';
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
        ->and($updated->counter)->toBe(4);
});
