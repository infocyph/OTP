<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;


test('HOTP replay state uses CacheLayer atomics without a lock', function () {
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
    $cache->expects($this->once())->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        0,
        null,
    )->willReturn(true);

    $result = (new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))->verifyWithResult(
        '755224',
        0,
        cache: $cache,
        factorId: 'atomic-hotp',
    );

    expect($result->matched)->toBeTrue()
        ->and($result->matchedCounter)->toBe(0)
        ->and($result->nextCounter)->toBe(1);
});

test('counter OCRA replay state uses the monotonic atomic path', function () {
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
    $cache->expects($this->once())->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        0,
        null,
    )->willReturn(true);

    $ocra = new OCRA(
        'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
        '12345678901234567890123456789012',
    );
    $code = $ocra->generate('12345678', 0, '1234');
    $result = $ocra->verifyWithResult(
        $code,
        '12345678',
        0,
        '1234',
        cache: $cache,
        factorId: 'atomic-ocra-counter',
    );

    expect($result->matched)->toBeTrue()
        ->and($result->matchedCounter)->toBe(0)
        ->and($result->nextCounter)->toBe(1);
});
