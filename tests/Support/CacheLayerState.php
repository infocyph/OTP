<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Cache\Lock\FileLockProvider;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use PHPUnit\Framework\MockObject\MockObject;

final class CacheLayerState
{
    public static function memory(): AuthenticationStateCacheInterface
    {
        return Cache::memory('otp-tests', self::options());
    }

    public static function sqlite(string $path): AuthenticationStateCacheInterface
    {
        return Cache::sqlite('otp-tests', $path, self::options());
    }

    /** @return AuthenticationStateCacheInterface&MockObject */
    public static function configureMock(
        AuthenticationStateCacheInterface&MockObject $cache,
        ?LockProviderInterface $locks = null,
    ): AuthenticationStateCacheInterface
    {
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn($locks ?? new FileLockProvider());

        return $cache;
    }

    private static function options(): CacheOptions
    {
        return new CacheOptions(
            integrityKey: str_repeat('i', 32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        );
    }
}
