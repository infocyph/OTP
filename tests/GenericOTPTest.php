<?php

require_once __DIR__.'/Support/InMemoryCacheItemPool.php';

use Infocyph\OTP\OTP;
use Infocyph\OTP\Tests\Support\InMemoryCacheItemPool;

test('Basic', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 3, 'xxh128', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    expect($otp)->toBeString()->toHaveLength(4);
    expect($otpInstance->verify($signature, $otp))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Duration', function () {
    $signature = random_bytes(3);
    $cachePool = new InMemoryCacheItemPool();
    $otpInstance = new OTP(4, 2, 3, 'xxh128', $cachePool);
    $otp = $otpInstance->generate($signature);
    $cachePool->expire('ao-otp_'.hash('xxh3', $signature));
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Retry with persistent key', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2, 'xxh128', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $invalidOtp = str_pad((string) ((((int) $otp) + 1) % 10000), 4, '0', STR_PAD_LEFT);
    expect($otpInstance->verify($signature, $invalidOtp, false))->toBeFalse();
    expect($otpInstance->verify($signature, $otp, false))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Retry with non-persistent key (delete key if key name matches)', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2, 'xxh128', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $invalidOtp = str_pad((string) ((((int) $otp) + 1) % 10000), 4, '0', STR_PAD_LEFT);
    expect($otpInstance->verify($signature, $invalidOtp))->toBeFalse();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Delete', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(6, 30, 3, 'xxh128', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $otpInstance->delete($signature);
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});

test('Flash', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(6, 30, 3, 'xxh128', new InMemoryCacheItemPool());
    $otp = $otpInstance->generate($signature);
    $otpInstance->flush();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});
