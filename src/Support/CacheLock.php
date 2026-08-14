<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/** @internal */
final class CacheLock
{
    private const float LEASE_SECONDS = 30.0;

    private const float WAIT_SECONDS = 1.0;

    public static function advance(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $value,
        ?int $ttl,
        string $stateName,
    ): bool {
        return self::synchronized(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use (
                $cache,
                $stateKey,
                $value,
                $ttl,
                $stateName,
            ): bool {
                $current = $cache->get($stateKey);
                if ($current !== null && !is_int($current)) {
                    throw new RuntimeException('Invalid ' . $stateName . ' state in CacheLayer.');
                }
                if ($current !== null && $value <= $current) {
                    return false;
                }

                self::ensureOwned($locks, $handle);
                if (!$cache->set($stateKey, $value, $ttl)) {
                    throw new RuntimeException('Unable to store ' . $stateName . ' state.');
                }

                return true;
            },
        );
    }

    public static function assertSafe(AuthenticationStateCacheInterface $cache): void
    {
        if ($cache->isFailOpen()) {
            throw new InvalidArgumentException('Authentication state caches must be configured fail-closed.');
        }
        if (!$cache->hasPayloadIntegrity()) {
            throw new InvalidArgumentException('Authentication state caches must enable payload integrity.');
        }
        if (!$cache->isAuthoritative()) {
            throw new InvalidArgumentException('Authentication state caches must use one authoritative direct backend.');
        }
        if ($cache->authenticationStateLock() === null) {
            throw new InvalidArgumentException('Authentication state caches must provide a coordinated lock capability.');
        }
    }

    public static function consumeOnce(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        return self::synchronized(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use (
                $cache,
                $stateKey,
                $ttl,
                $stateName,
            ): bool {
                $current = $cache->get($stateKey);
                if ($current !== null && $current !== 1) {
                    throw new RuntimeException('Invalid ' . $stateName . ' token in CacheLayer.');
                }
                if ($current === 1) {
                    return false;
                }

                self::ensureOwned($locks, $handle);
                if (!$cache->set($stateKey, 1, $ttl)) {
                    throw new RuntimeException('Unable to store ' . $stateName . ' token.');
                }

                return true;
            },
        );
    }

    public static function ensureOwned(LockProviderInterface $locks, LockHandle $handle): void
    {
        if (!$locks->refresh($handle, self::LEASE_SECONDS)) {
            throw new RuntimeException('The OTP state lock was lost before mutation.');
        }
    }

    /**
     * Release is post-operation cleanup: it never replaces a committed result or
     * the primary operation failure. The lock lease bounds failed cleanup.
     *
     * @template T
     * @param AuthenticationStateCacheInterface $cache Configured authentication-state cache.
     * @param string $key State coordination lock key.
     * @param callable(LockProviderInterface, LockHandle): T $operation
     * @return T
     */
    public static function synchronized(
        AuthenticationStateCacheInterface $cache,
        string $key,
        callable $operation,
    ): mixed {
        self::assertSafe($cache);
        $locks = $cache->authenticationStateLock()
            ?? throw new InvalidArgumentException('Authentication state caches must provide a coordinated lock capability.');
        $handle = $locks->acquire($key, self::WAIT_SECONDS, self::LEASE_SECONDS)
            ?? throw new RuntimeException('Unable to acquire the OTP state lock.');

        try {
            $result = $operation($locks, $handle);
        } catch (Throwable $failure) {
            try {
                $locks->release($handle);
            } catch (Throwable) {
            }

            throw $failure;
        }

        try {
            $locks->release($handle);
        } catch (Throwable) {
        }

        return $result;
    }
}
