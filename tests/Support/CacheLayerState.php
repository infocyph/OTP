<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Cache\Lock\FileLockProvider;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use PHPUnit\Framework\MockObject\Stub;
use RuntimeException;

final class CacheLayerState
{
    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \LogicException
     */
    public static function memory(): AuthenticationStateCacheInterface
    {
        return Cache::memory('otp-tests', self::options());
    }

    /**
     * @return \Closure(): Cache
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \RuntimeException
     */
    public static function pdoFactory(string $backend): \Closure
    {
        $dsn = getenv('IC_' . $backend . '_DSN');
        $username = getenv('IC_' . $backend . '_USER');
        $password = getenv('IC_' . $backend . '_PASSWORD');
        if (!is_string($dsn) || $dsn === '' || !is_string($username) || !is_string($password)) {
            throw new RuntimeException('The configured native PDO OTP test service is required.');
        }
        $namespace = 'otp-pdo-' . bin2hex(random_bytes(8));
        $options = new CacheOptions(
            integrityKey: random_bytes(32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        );
        return static fn(): Cache => Cache::pdo($namespace, $dsn, $username, $password, options: $options);
    }

    /**
     * @throws \RuntimeException
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\CacheLayer\Cache\Lock\UnsupportedPdoLockDriver
     * @throws \LogicException
     */
    public static function sqlite(string $path): AuthenticationStateCacheInterface
    {
        if (!extension_loaded('pdo_sqlite')) {
            throw new RuntimeException('SQLite authentication-state tests require the pdo_sqlite extension.');
        }

        return Cache::sqlite('otp-tests', $path, self::options());
    }

    /**
     * @template T of AuthenticationStateCacheInterface&Stub
     * @param T $cache
     * @return T
     */
    public static function configureMock(
        AuthenticationStateCacheInterface&Stub $cache,
        ?LockProviderInterface $locks = null,
    ): AuthenticationStateCacheInterface
    {
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn($locks ?? new FileLockProvider());

        return $cache;
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     */
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
