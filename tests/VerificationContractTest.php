<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\VerificationReason;


test('verification reason contract remains stable', function () {
    expect(array_map(
        static fn (VerificationReason $reason): string => $reason->value,
        VerificationReason::cases(),
    ))->toBe([
        'drifted',
        'malformed',
        'matched',
        'mismatch',
        'replay',
        'resynchronized',
    ]);
});

test('credential failures remain structured results', function () {
    $totp = new TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    $hotp = new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');

    expect($totp->verifyWithWindow('bad', 3_000)->reason)->toBe(VerificationReason::Malformed)
        ->and($totp->verifyWithWindow('000000', 3_000)->reason)->toBe(VerificationReason::Mismatch)
        ->and($hotp->verifyWithResult('bad', 0)->reason)->toBe(VerificationReason::Malformed)
        ->and($hotp->verifyWithResult('000000', 0)->reason)->toBe(VerificationReason::Mismatch);
});

test('monotonic replay backend failures propagate instead of becoming credential results', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->method('get')->willThrowException(new RuntimeException('backend read failed'));

    $totp = new TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    $code = $totp->generate(3_000);

    expect(fn () => $totp->verifyWithWindow(
        $code,
        3_000,
        cache: $cache,
        factorId: 'taxonomy-totp',
    ))->toThrow(RuntimeException::class, 'backend read failed');
});

test('one-time replay backend failures propagate instead of becoming replay', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $atomic->method('setIfAbsent')->willThrowException(new RuntimeException('backend claim failed'));

    $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');

    expect(fn () => $ocra->verifyWithResult(
        $ocra->generate('00000000'),
        '00000000',
        cache: $cache,
        factorId: 'taxonomy-ocra',
        replayTtl: 300,
    ))->toThrow(RuntimeException::class, 'backend claim failed');
});
