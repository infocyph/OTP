<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\OTP\AOTP;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\VerificationReason;
use RuntimeException;

test('native PDO OTP state is shared and consumed exactly once across connections', function (string $backend): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $key = random_bytes(32);
    $binding = 'native-pdo-replay';
    $stateKey = hash('sha256', "infocyph:otp:generic:state:v1\0" . $binding);

    try {
        expect(CacheLock::stateAtomic($cache))->not->toBeNull();
        $otp = new GenericOtp($cache, $key);
        $proof = $otp->generate($binding);
        $independent = $factory();
        expect($independent->get($stateKey))->toBeArray();

        $results = Concurrency::run(
            static fn(): int => (int) new GenericOtp($factory(), $key)->verify($binding, $proof),
            4,
        );

        expect(array_sum($results))->toBe(1)
            ->and(new GenericOtp($independent, $key)->verify($binding, $proof))->toBeFalse();

        $replacement = $otp->generate($binding);
        expect(new GenericOtp($independent, $key)->verify($binding, $replacement))->toBeTrue()
            ->and($otp->verify($binding, $replacement))->toBeFalse();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO OCRA claims an initially absent replay record once and isolates replacement factors', function (string $backend): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');
    $challenge = '00000000';
    $proof = $ocra->generate($challenge);
    $stateKey = '05736871982693a8886385eabc65c0c0bb1f63f5c0bcc6d29c68b7ab05d00503';

    try {
        expect($cache->get($stateKey))->toBeNull();
        $results = Concurrency::run(
            static fn(): int => (int) $ocra->verifyWithResult(
                $proof,
                $challenge,
                cache: $factory(),
                factorId: 'factor-v1',
                replayTtl: 300,
            )->matched,
            4,
        );
        $independent = $factory();
        expect(array_sum($results))->toBe(1)
            ->and($independent->get($stateKey))->toBe(1)
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $independent, factorId: 'factor-v1', replayTtl: 300)->matched)->toBeFalse()
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $independent, factorId: 'factor-v2', replayTtl: 300)->matched)->toBeTrue()
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $cache, factorId: 'factor-v2', replayTtl: 300)->matched)->toBeFalse();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO GenericOtp preserves expiry and attempt ownership across independent writers', function (string $backend): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $independent = $factory();
    $key = random_bytes(32);
    $binding = 'native-pdo-expiry';
    $stateKey = hash('sha256', "infocyph:otp:generic:state:v1\0" . $binding);
    $otp = new GenericOtp($cache, $key, maxAttempts: 3);
    $verifier = new GenericOtp($independent, $key, maxAttempts: 3);

    try {
        $proof = $otp->generate($binding);
        $wrong = $proof === '000000' ? '000001' : '000000';
        $initial = $independent->get($stateKey);
        if (!is_array($initial) || !is_int($initial['expiresAt'] ?? null)) {
            throw new RuntimeException('Missing native OTP expiry record.');
        }

        expect(Concurrency::run(
            static fn(): int => (int) new GenericOtp($factory(), $key, maxAttempts: 3)->verify($binding, $wrong),
            2,
        ))->toBe([0, 0]);
        expect($independent->get($stateKey))->toBe(array_replace($initial, ['remainingAttempts' => 1]));

        expect($verifier->verify($binding, $wrong))->toBeFalse()
            ->and($otp->verify($binding, $proof))->toBeFalse();

        $proof = $otp->generate($binding);
        $expired = $independent->get($stateKey);
        if (!is_array($expired)) {
            throw new RuntimeException('Missing native OTP replacement record.');
        }

        // Keep the backend row live while its authenticated challenge is expired.
        $expired['expiresAt'] = time() - 1;
        expect($independent->set($stateKey, $expired, 300))->toBeTrue()
            ->and($otp->verify($binding, $proof))->toBeFalse();

        $proof = $otp->generate($binding);
        expect($verifier->delete($binding))->toBeTrue()
            ->and($otp->verify($binding, $proof))->toBeFalse()
            ->and($independent->get($stateKey))->toBeNull();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO AOTP reserves and consumes a signed challenge for exactly one owner', function (string $backend): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    try {
        $challenge = $aotp->issue($cache, 'factor-v1', 'login:flow-a', now: 1_000);
        $response = AOTP::respond($keys->privateKey, $challenge, 'login.example.com', 'login:flow-a', now: 1_001);
        $stateKey = hash('sha256', "infocyph:otp:aotp:state:v1\0factor-v1\0" . hash('sha256', $challenge->signingPayload(), true));
        $independent = $factory();
        expect($independent->get($stateKey))->toBe(0)
            ->and($aotp->verify($independent, 'factor-v2', $challenge, $response, 1_001))->toBeFalse()
            ->and($independent->get($stateKey))->toBe(0);

        $results = Concurrency::run(
            static fn(): int => (int) $aotp->verify($factory(), 'factor-v1', $challenge, $response, 1_001),
            4,
        );
        expect(array_sum($results))->toBe(1)
            ->and($independent->get($stateKey))->toBe(1)
            ->and($aotp->verifyWithResult($independent, 'factor-v1', $challenge, $response, 1_002)->reason)
            ->toBe(VerificationReason::Replay);
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO GridOTP keeps challenge ownership and consumption serializable', function (string $backend): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $secret = GridOTP::generateSecret();
    $grid = new GridOTP($cache, $secret);
    try {
        $challenge = $grid->issue('factor-v1', now: 1_000);
        $response = GridOTP::respond($challenge, $secret);
        $stateKey = hash('sha256', "infocyph:otp:gridotp:state:v1\0factor-v1\0" . $challenge->id);
        $independent = $factory();
        $initial = $independent->get($stateKey);
        if (!is_array($initial)) {
            throw new RuntimeException('Expected a native GridOTP challenge record.');
        }
        expect($initial['consumed'] ?? null)->toBeFalse()
            ->and(new GridOTP($independent, $secret)->verify('factor-v2', $challenge, $response, 1_001))->toBeFalse()
            ->and($independent->get($stateKey))->toBe($initial);

        $results = Concurrency::run(
            static fn(): int => (int) new GridOTP($factory(), $secret)->verify('factor-v1', $challenge, $response, 1_001),
            4,
        );
        $consumed = $independent->get($stateKey);
        if (!is_array($consumed)) {
            throw new RuntimeException('Expected a native GridOTP consumed record.');
        }
        expect(array_sum($results))->toBe(1)
            ->and($consumed['consumed'] ?? null)->toBeTrue()
            ->and($consumed['expiresAt'] ?? null)->toBe($initial['expiresAt'] ?? null)
            ->and(new GridOTP($independent, $secret)->verifyWithResult('factor-v1', $challenge, $response, 1_002)->reason)
            ->toBe(VerificationReason::Replay);
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);
