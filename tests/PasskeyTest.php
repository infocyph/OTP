<?php

declare(strict_types=1);

use Infocyph\OTP\Passkey;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\ValueObjects\PasskeyCeremony;
use Infocyph\OTP\VerificationReason;

test('passkey dependency is available in the development matrix', function () {
    expect(Passkey::isAvailable())->toBeTrue();
});

test('passkey registration creates discoverable user-verified options', function () {
    $service = new Passkey(
        CacheLayerState::memory(),
        'example.com',
        'Example',
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
        ->and($options['rp']['name'] ?? null)->toBe('Example')
        ->and($options['user']['name'] ?? null)->toBe('alice@example.com')
        ->and($options['authenticatorSelection']['residentKey'] ?? null)->toBe('required')
        ->and($options['authenticatorSelection']['userVerification'] ?? null)->toBe('required')
        ->and($options['attestation'] ?? null)->toBe('none');
});

test('passkey authentication supports discoverable credentials', function () {
    $service = new Passkey(
        CacheLayerState::memory(),
        'example.com',
        'Example',
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
        'Example',
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
        ->and($second->reason)->toBe(VerificationReason::Malformed);
});

test('consumed passkey ceremony state reports replay before parsing another response', function () {
    $cache = CacheLayerState::memory();
    $service = new Passkey($cache, 'example.com', 'Example', ['https://example.com'], ttlSeconds: 60);
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
    $service = new Passkey($cache, 'example.com', 'Example', ['https://example.com'], ttlSeconds: 10);
    $ceremony = $service->beginRegistration('binding', 'user-handle', 'alice', 'Alice', now: 100);
    $stateKey = hash('sha256', "infocyph:otp:passkey:state:v1\0binding\0" . $ceremony->id);

    $result = $service->finishRegistration('binding', $ceremony->id, '{}', 111);

    expect($result->reason)->toBe(VerificationReason::Mismatch)
        ->and($cache->get($stateKey))->toBeNull();
});

test('passkey configuration rejects unsafe relying party input', function () {
    $cache = CacheLayerState::memory();

    expect(fn () => new Passkey($cache, 'https://example.com', 'Example', ['https://example.com']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Passkey($cache, 'example.com', 'Example', ['http://example.com']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Passkey($cache, 'example.com', '', ['https://example.com']))
        ->toThrow(InvalidArgumentException::class);
});
