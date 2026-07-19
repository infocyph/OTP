<?php

declare(strict_types=1);

require_once __DIR__.'/Support/InMemoryCacheItemPool.php';

use Infocyph\OTP\OTP;
use Infocyph\OTP\Tests\Support\InMemoryCacheItemPool;

test('Basic', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 3, 'sha256', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    expect($otp)->toBeString()->toHaveLength(4);
    expect($otpInstance->verify($signature, $otp))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Duration', function () {
    $signature = random_bytes(3);
    $cachePool = new InMemoryCacheItemPool();
    $otpInstance = new OTP(4, 2, 3, 'sha256', $cachePool);
    $otp = $otpInstance->generate($signature);
    $cachePool->expire('ao-otp_'.hash('sha256', $signature));
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Retry with persistent key', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2, 'sha256', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $invalidOtp = str_pad((string) ((((int) $otp) + 1) % 10000), 4, '0', STR_PAD_LEFT);
    expect($otpInstance->verify($signature, $invalidOtp, false))->toBeFalse();
    expect($otpInstance->verify($signature, $otp, false))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Retry with non-persistent key (delete key if key name matches)', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2, 'sha256', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $invalidOtp = str_pad((string) ((((int) $otp) + 1) % 10000), 4, '0', STR_PAD_LEFT);
    expect($otpInstance->verify($signature, $invalidOtp))->toBeFalse();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Delete', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(6, 30, 3, 'sha256', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $otpInstance->delete($signature);
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});

test('Flash', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(6, 30, 3, 'sha256', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $otpInstance->flush();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});

test('Configuration rejects unsafe hashes and invalid bounds', function () {
    $cache = new InMemoryCacheItemPool();

    expect(fn () => new OTP(hashAlgorithm: 'xxh128', cacheAdapter: $cache))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new OTP(digitCount: 3, cacheAdapter: $cache))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new OTP(validUpto: 0, cacheAdapter: $cache))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new OTP(validUpto: 86401, cacheAdapter: $cache))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new OTP(retry: 101, cacheAdapter: $cache))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new OTP(cacheAdapter: $cache, hashKey: 'short'))
        ->toThrow(InvalidArgumentException::class);
});

test('Generic OTP supports a purpose-specific HMAC key', function () {
    $signature = random_bytes(16);
    $otp = new OTP(
        cacheAdapter: new InMemoryCacheItemPool(),
        hashKey: str_repeat('k', 32),
    );
    $code = $otp->generate($signature);

    expect($otp->verify($signature, $code))->toBeTrue();
});

test('Malformed generic OTP values fail without consuming valid state', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(cacheAdapter: new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);

    expect($otpInstance->verify($signature, 'invalid'))->toBeFalse()
        ->and($otpInstance->verify($signature, $otp))->toBeTrue();
});
