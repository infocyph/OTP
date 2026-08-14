<?php

declare(strict_types=1);

use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\Tests\Support\RedisState;

beforeEach(function () {
    if (!RedisState::available()) {
        $this->markTestSkipped('A live Redis/Valkey service with phpredis is required.');
    }
});

test('Redis serializes generic OTP success and failed-attempt races', function () {
    $namespace = 'otp-redis-generic-' . getmypid();
    RedisState::cache($namespace)->clear();
    $key = str_repeat('g', 32);
    $binding = 'redis-generic-factor';
    $service = new GenericOtp(RedisState::cache($namespace), $key, maxAttempts: 3);
    $code = $service->generate($binding);

    $valid = Concurrency::run(static function () use ($namespace, $key, $binding, $code): int {
        return (new GenericOtp(RedisState::cache($namespace), $key, maxAttempts: 3))
            ->verify($binding, $code) ? 1 : 0;
    });
    sort($valid);
    expect($valid)->toBe([0, 1]);

    $code = $service->generate($binding);
    $wrong = $code === '000000' ? '000001' : '000000';
    expect(Concurrency::run(static function () use ($namespace, $key, $binding, $wrong): int {
        return (new GenericOtp(RedisState::cache($namespace), $key, maxAttempts: 3))
            ->verify($binding, $wrong) ? 1 : 0;
    }))->toBe([0, 0])
        ->and($service->verify($binding, $wrong))->toBeFalse()
        ->and($service->verify($binding, $code))->toBeFalse();
})->group('redis');

test('Redis serializes TOTP HOTP and OCRA replay races', function (string $primitive) {
    $namespace = 'otp-redis-' . strtolower($primitive) . '-' . getmypid();
    RedisState::cache($namespace)->clear();
    $totpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    $totpCode = (new TOTP($totpSecret))->generate(2_000_000_000);
    $results = Concurrency::run(static function () use ($namespace, $primitive, $totpCode, $totpSecret): int {
        $cache = RedisState::cache($namespace);

        return match ($primitive) {
            'TOTP' => (new TOTP($totpSecret))
                ->verifyWithWindow($totpCode, 2_000_000_000, cache: $cache, factorId: 'redis-totp')
                ->matched ? 1 : 0,
            'HOTP' => (new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
                ->verifyWithResult('755224', 0, cache: $cache, factorId: 'redis-hotp')
                ->matched ? 1 : 0,
            'OCRA' => (new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890'))
                ->verifyWithResult(
                    '237653',
                    '00000000',
                    cache: $cache,
                    factorId: 'redis-ocra',
                    replayTtl: 300,
                )->matched ? 1 : 0,
            default => 250,
        };
    });
    sort($results);

    expect($results)->toBe([0, 1]);
})->with(['TOTP', 'HOTP', 'OCRA'])->group('redis');
