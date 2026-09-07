<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;


test('TOTP keeps the v1 replay-state key', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        '3b37a43e97fa59b71c367a7a2321d718e454126307b02b6549bb5e58521b2bfe',
        100,
        30,
    )->willReturn(true);

    $totp = new TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect($totp->verifyWithWindow($totp->generate(3_000), 3_000, cache: $cache, factorId: 'factor-v1')->matched)
        ->toBeTrue();
});

test('HOTP keeps the v1 replay-state key', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        'ed3e9fa7398752a5a573b6ead0b81e9a9879fa057476cf21ab40dcd8db593439',
        0,
        null,
    )->willReturn(true);

    expect((new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
        ->verifyWithResult('755224', 0, cache: $cache, factorId: 'factor-v1')->matched)->toBeTrue();
});

test('counter OCRA keeps the v1 replay-state key', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->method('get')->willReturn(null);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        '1920e10575738d81e851fb5f7cf474e37b92b8c10b75845d61ab5ffde6bccf83',
        0,
        null,
    )->willReturn(true);

    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', '12345678901234567890123456789012');
    $code = $ocra->generate('12345678', 0);
    expect($ocra->verifyWithResult($code, '12345678', 0, cache: $cache, factorId: 'factor-v1')->matched)
        ->toBeTrue();
});

test('non-counter OCRA keeps the v1 message replay-state key', function () {
    $atomic = $this->createMock(AtomicCacheInterface::class);
    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $atomic->expects($this->once())->method('setIfAbsent')->with(
        '05736871982693a8886385eabc65c0c0bb1f63f5c0bcc6d29c68b7ab05d00503',
        1,
        300,
    )->willReturn(true);

    $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');
    expect($ocra->verifyWithResult(
        '237653',
        '00000000',
        cache: $cache,
        factorId: 'factor-v1',
        replayTtl: 300,
    )->matched)->toBeTrue();
});

test('GenericOtp keeps its v1 state and lock keys', function () {
    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $locks = $this->createMock(LockProviderInterface::class);
    $handle = new LockHandle(
        'de29a92d9fb4a09365b43492f7cc177e79a9c6e9b3070e1a0a327f901cc1ce91',
        'token',
    );
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn($locks);
    $locks->expects($this->once())->method('acquire')->with(
        'de29a92d9fb4a09365b43492f7cc177e79a9c6e9b3070e1a0a327f901cc1ce91',
        1.0,
        30.0,
    )->willReturn($handle);
    $locks->method('refresh')->willReturn(true);
    $locks->method('release');
    $cache->expects($this->once())->method('set')->with(
        'fa922a4eaa6817579b5c9c46517c6df43f02a07ef2653596e14ba95d1e7b1169',
        $this->isType('array'),
        300,
    )->willReturn(true);

    expect((new GenericOtp($cache, str_repeat('g', 32)))->generate('binding-v1'))->toHaveLength(6);
});
