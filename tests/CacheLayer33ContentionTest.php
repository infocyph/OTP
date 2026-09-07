<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\TOTP;


test('atomic replay contention is bounded and fails closed', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->expects($this->never())->method('authenticationStateLock');
    $cache->expects($this->exactly(8))->method('get')->willReturn(99);
    $atomic->expects($this->exactly(8))->method('compareAndSet')->willReturn(false);

    $totp = new TOTP(TOTP::generateSecret(), period: 30);

    expect(fn () => $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        cache: $cache,
        factorId: 'atomic-contention',
    ))->toThrow(RuntimeException::class, 'after atomic contention');
});

test('replay protection rejects a cache with neither atomics nor a coordinated lock', function () {
    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn(null);

    $totp = new TOTP(TOTP::generateSecret(), period: 30);

    expect(fn () => $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        cache: $cache,
        factorId: 'missing-capability',
    ))->toThrow(InvalidArgumentException::class, 'atomic or coordinated lock capability');
});
