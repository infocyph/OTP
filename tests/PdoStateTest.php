<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\OTP\AOTP;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\MobileOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\TOTP;
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

test('native PDO monotonic OTP transitions elect one winner and never regress across factor generations', function (string $backend, string $factor): void {
    $factory = CacheLayerState::pdoFactory($backend);
    $cache = $factory();
    $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    [$domain, $lowValue, $highValue] = match ($factor) {
        'TOTP' => ['totp:timestep', 100, 101],
        'HOTP' => ['hotp:counter', 42, 43],
        'MobileOTP' => ['mobile:timestep', 300, 301],
        'OCRA' => ['ocra:counter', 42, 43],
        default => throw new RuntimeException('Unknown monotonic protocol fixture.'),
    };
    $stateKey = static fn (string $owner): string => hash('sha256', 'infocyph:otp:' . $domain . ":v1\0" . $owner);
    $admit = static function (Cache $target, bool $higher, string $owner) use ($factor, $secret): VerificationResult {
        $counter = $higher ? 43 : 42;
        $time = $higher ? 3_030 : 3_000;
        $mobileTime = $higher ? 3_010 : 3_000;

        return match ($factor) {
            'TOTP' => new TOTP($secret)->verifyWithWindow(
                new TOTP($secret)->generate($time),
                $time,
                cache: $target,
                factorId: $owner,
            ),
            'HOTP' => new HOTP($secret)->verifyWithResult(
                new HOTP($secret)->generate($counter),
                $counter,
                cache: $target,
                factorId: $owner,
            ),
            'MobileOTP' => new MobileOTP('0123456789abcdef', '1234')->verifyWithWindow(
                new MobileOTP('0123456789abcdef', '1234')->generate($mobileTime),
                $mobileTime,
                cache: $target,
                factorId: $owner,
            ),
            'OCRA' => new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', str_repeat('k', 32))->verifyWithResult(
                new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', str_repeat('k', 32))->generate('12345678', $counter),
                '12345678',
                $counter,
                cache: $target,
                factorId: $owner,
            ),
            default => throw new RuntimeException('Unknown monotonic protocol fixture.'),
        };
    };

    try {
        expect($cache->get($stateKey('factor-v1')))->toBeNull();
        $same = Concurrency::run(
            static fn(): int => (int) $admit($factory(), false, 'factor-v1')->matched,
            4,
        );
        $independent = $factory();
        expect(array_sum($same))->toBe(1)
            ->and($independent->get($stateKey('factor-v1')))->toBe($lowValue)
            ->and($admit($independent, false, 'factor-v1')->replayDetected)->toBeTrue()
            ->and($independent->get($stateKey('factor-v2')))->toBeNull();

        $ordered = Concurrency::run(
            static fn (int $worker): int => $admit($factory(), $worker === 1, 'factor-v2')->matched ? $worker + 1 : 0,
            2,
        );
        expect($ordered)->toContain(2)
            ->and($independent->get($stateKey('factor-v2')))->toBe($highValue)
            ->and($admit($independent, false, 'factor-v2')->replayDetected)->toBeTrue()
            ->and($admit($independent, true, 'factor-v2')->replayDetected)->toBeTrue()
            ->and($independent->get($stateKey('factor-v1')))->toBe($lowValue);
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES'])->with(['TOTP', 'HOTP', 'MobileOTP', 'OCRA']);
