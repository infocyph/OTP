<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;

/**
 * @return AuthenticationStateCacheInterface&AtomicCacheProviderInterface
 */
function atomicAuthenticationCache(object $test, AtomicCacheInterface $atomic): object
{
    $cache = $test->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);

    return $cache;
}

test('TOTP uses CacheLayer atomics without acquiring a replay lock', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = atomicAuthenticationCache($this, $atomic);
    $cache->expects($this->never())->method('authenticationStateLock');
    $cache->expects($this->once())->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        100,
        30,
    )->willReturn(true);

    $totp = new TOTP(TOTP::generateSecret(), period: 30);
    $result = $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        cache: $cache,
        factorId: 'atomic-totp',
    );

    expect($result->matched)->toBeTrue();
});

test('TOTP resolves an atomic CAS race as replay without state regression', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = atomicAuthenticationCache($this, $atomic);
    $cache->expects($this->never())->method('authenticationStateLock');
    $cache->expects($this->exactly(2))->method('get')->willReturnOnConsecutiveCalls(99, 100);
    $atomic->expects($this->once())->method('compareAndSet')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        99,
        100,
        30,
    )->willReturn(false);

    $totp = new TOTP(TOTP::generateSecret(), period: 30);
    $result = $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        cache: $cache,
        factorId: 'atomic-race',
    );

    expect($result->matched)->toBeFalse()
        ->and($result->replayDetected)->toBeTrue();
});

test('non-counter OCRA claims replay state with one atomic set-if-absent', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = atomicAuthenticationCache($this, $atomic);
    $cache->expects($this->never())->method('authenticationStateLock');
    $cache->expects($this->never())->method('get');
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        1,
        300,
    )->willReturn(true);

    $result = (new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890'))->verifyWithResult(
        '237653',
        '00000000',
        cache: $cache,
        factorId: 'atomic-ocra',
        replayTtl: 300,
    );

    expect($result->matched)->toBeTrue();
});

test('atomic OCRA replay rejects corrupted existing state', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = atomicAuthenticationCache($this, $atomic);
    $cache->expects($this->never())->method('authenticationStateLock');
    $cache->expects($this->once())->method('get')->willReturn(2);
    $atomic->expects($this->once())->method('setIfAbsent')->willReturn(false);

    expect(fn () => (new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890'))->verifyWithResult(
        '237653',
        '00000000',
        cache: $cache,
        factorId: 'atomic-corrupt',
        replayTtl: 300,
    ))->toThrow(RuntimeException::class, 'Invalid OCRA replay token in CacheLayer.');
});

test('GenericOtp still requires the coordinated lock capability', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = atomicAuthenticationCache($this, $atomic);
    $cache->expects($this->once())->method('authenticationStateLock')->willReturn(null);

    expect(fn () => new GenericOtp($cache, str_repeat('g', 32)))
        ->toThrow(InvalidArgumentException::class, 'coordinated lock capability');
});
