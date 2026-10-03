<?php

declare(strict_types=1);

use Infocyph\OTP\GridOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\ValueObjects\GridChallenge;
use Infocyph\OTP\VerificationReason;

test('GridOTP generates a dynamic balanced grid and verifies its response once', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret);
    $challenge = $gridOtp->issue('user-42:grid:v1', now: 1_000);
    $response = GridOTP::respond($challenge, $secret);
    $counts = array_count_values($challenge->grid);

    $challengedSymbols = array_map(
        static fn (int $position): string => $secret[$position - 1],
        $challenge->positions,
    );

    expect($secret)->toMatch('/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{12}$/')
        ->and(count(array_unique(str_split($secret))))->toBeGreaterThanOrEqual(10)
        ->and($challenge->positions)->toHaveCount(6)
        ->and(array_unique($challengedSymbols))->toHaveCount(6)
        ->and($challenge->grid)->toHaveCount(32)
        ->and(min($counts))->toBe(3)
        ->and(max($counts))->toBe(4)
        ->and($response)->toMatch('/^\d{6}$/')
        ->and($gridOtp->verify('user-42:grid:v1', $challenge, $response, 1_001))->toBeTrue()
        ->and($gridOtp->verifyWithResult('user-42:grid:v1', $challenge, $response, 1_002)->reason)
        ->toBe(VerificationReason::Replay);
});

test('GridOTP failed responses decrement attempts without extending expiry', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret, maxAttempts: 2);
    $challenge = $gridOtp->issue('factor', now: 1_000);
    $correct = GridOTP::respond($challenge, $secret);
    $wrong = str_repeat($correct[0] === '0' ? '1' : '0', strlen($correct));

    expect($gridOtp->verify('factor', $challenge, $wrong, 1_001))->toBeFalse()
        ->and($gridOtp->verify('factor', $challenge, $wrong, 1_002))->toBeFalse()
        ->and($gridOtp->verify('factor', $challenge, $correct, 1_003))->toBeFalse();
});

test('GridOTP malformed response does not consume an attempt', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret, maxAttempts: 1);
    $challenge = $gridOtp->issue('factor', now: 1_000);
    $correct = GridOTP::respond($challenge, $secret);

    expect($gridOtp->verifyWithResult('factor', $challenge, 'bad', 1_001)->reason)
        ->toBe(VerificationReason::Malformed)
        ->and($gridOtp->verify('factor', $challenge, $correct, 1_002))->toBeTrue();
});

test('GridOTP binds cached state to grid positions and challenge metadata', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret);
    $issued = $gridOtp->issue('factor', now: 1_000);
    $positions = $issued->positions;
    [$positions[0], $positions[1]] = [$positions[1], $positions[0]];
    $tampered = new GridChallenge(
        $issued->id,
        $issued->grid,
        $positions,
        $issued->secretLength,
        $issued->issuedAt,
        $issued->expiresAt,
    );
    $tamperedResponse = GridOTP::respond($tampered, $secret);
    $correctResponse = GridOTP::respond($issued, $secret);

    expect($gridOtp->verifyWithResult('factor', $tampered, $tamperedResponse, 1_001)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($gridOtp->verify('factor', $issued, $correctResponse, 1_002))->toBeTrue();
});

test('GridOTP challenges round-trip through transport arrays', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret);
    $challenge = $gridOtp->issue('factor', now: 1_000);
    $parsed = GridChallenge::fromArray($challenge->toArray());

    expect($parsed->canonicalPayload())->toBe($challenge->canonicalPayload())
        ->and($parsed->grid)->toBe($challenge->grid)
        ->and($parsed->positions)->toBe($challenge->positions)
        ->and($parsed->__debugInfo()['grid'])->toBe('[redacted]');
});

test('GridOTP generated secrets guarantee challenge-capable symbol diversity', function (int $length) {
    $secret = GridOTP::generateSecret($length);

    expect(strlen($secret))->toBe($length)
        ->and(count(array_unique(str_split($secret))))->toBeGreaterThanOrEqual(min(10, $length));
})->with([8, 9, 10, 12, 32]);

test('GridOTP exposes migration-safe diversity policy for enrolled secrets', function () {
    $cache = CacheLayerState::memory();
    $legacySecret = 'AAAAAAAA';
    $strongSecret = 'AABBCCDDEEFF';

    expect(GridOTP::hasSufficientDiversity($legacySecret))->toBeFalse()
        ->and(GridOTP::hasSufficientDiversity($strongSecret))->toBeTrue()
        ->and(fn () => new GridOTP($cache, $legacySecret, enforceDiversity: true))
        ->toThrow(InvalidArgumentException::class);

    $legacy = new GridOTP($cache, $legacySecret);
    $legacyChallenge = $legacy->issue('legacy-factor', now: 1_000);
    $legacyResponse = GridOTP::respond($legacyChallenge, $legacySecret);

    expect($legacy->verify('legacy-factor', $legacyChallenge, $legacyResponse, 1_001))->toBeTrue();

    $strong = new GridOTP($cache, $strongSecret, enforceDiversity: true);
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $challenge = $strong->issue('strong-factor-' . $attempt, now: 2_000 + $attempt);
        $challengedSymbols = array_map(
            static fn (int $position): string => $strongSecret[$position - 1],
            $challenge->positions,
        );

        expect(array_unique($challengedSymbols))->toHaveCount(6);
    }
});

test('GridOTP validates secrets and configuration bounds', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();

    expect(fn () => GridOTP::generateSecret(7))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GridOTP($cache, 'password'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GridOTP($cache, $secret, challengeSize: 5))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GridOTP($cache, $secret, ttlSeconds: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GridOTP($cache, $secret, maxAttempts: 0))->toThrow(InvalidArgumentException::class);
});

test('GridOTP expiry and factor binding fail closed', function () {
    $cache = CacheLayerState::memory();
    $secret = GridOTP::generateSecret();
    $gridOtp = new GridOTP($cache, $secret, ttlSeconds: 60);
    $challenge = $gridOtp->issue('factor-a', now: 1_000);
    $response = GridOTP::respond($challenge, $secret);

    expect($gridOtp->verifyWithResult('factor-b', $challenge, $response, 1_001)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($gridOtp->verifyWithResult('factor-a', $challenge, $response, 1_060)->reason)
        ->toBe(VerificationReason::Mismatch);
});

test('GridOTP concurrent verification accepts exactly one request', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-grid-');
    if ($path === false) {
        throw new RuntimeException('Unable to create GridOTP concurrency database.');
    }
    $secret = GridOTP::generateSecret();
    $service = new GridOTP(CacheLayerState::sqlite($path), $secret);
    $challenge = $service->issue('factor', now: 1_000);
    $response = GridOTP::respond($challenge, $secret);

    $results = Concurrency::run(static function () use ($path, $secret, $challenge, $response): int {
        $worker = new GridOTP(CacheLayerState::sqlite($path), $secret);

        return $worker->verify('factor', $challenge, $response, 1_001) ? 1 : 0;
    });

    unlink($path);
    expect(array_sum($results))->toBe(1);
});
