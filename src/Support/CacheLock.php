<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\CacheLayer\Cache\Lock\MemcachedLockProvider;
use Infocyph\CacheLayer\Cache\Lock\RedisLockProvider;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/** @internal */
final class CacheLock
{
    private const float LEASE_SECONDS = 30.0;

    private const int MAX_ATOMIC_ATTEMPTS = 8;

    private const float WAIT_SECONDS = 1.0;

    public static function advance(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $value,
        ?int $ttl,
        string $stateName,
    ): bool {
        $atomic = self::assertSafe($cache);
        if ($atomic !== null) {
            return self::advanceAtomically($cache, $atomic, $stateKey, $value, $ttl, $stateName);
        }

        return self::advanceWithLock($cache, $stateKey, $lockKey, $value, $ttl, $stateName);
    }

    public static function assertLockSafe(AuthenticationStateCacheInterface $cache): void
    {
        self::assertSafe($cache);
        if ($cache->authenticationStateLock() === null) {
            throw new InvalidArgumentException('Authentication state caches must provide a coordinated lock capability.');
        }
    }

    public static function assertSafe(AuthenticationStateCacheInterface $cache): ?AtomicCacheInterface
    {
        self::assertAuthenticationStateSafe($cache);
        $atomic = self::atomicCapability($cache);
        if ($atomic !== null) {
            return $atomic;
        }

        $locks = $cache->authenticationStateLock();
        if ($locks === null) {
            throw new InvalidArgumentException(
                'Authentication state caches must provide an atomic or coordinated lock capability.',
            );
        }
        if (self::lockRequiresAtomic($locks)) {
            throw new InvalidArgumentException(
                'Lease-based authentication state locks require a backend atomic capability.',
            );
        }

        return null;
    }

    public static function consumeOnce(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        $atomic = self::assertSafe($cache);
        if ($atomic !== null) {
            return self::consumeOnceAtomically($cache, $atomic, $stateKey, $ttl, $stateName);
        }

        return self::consumeOnceWithLock($cache, $stateKey, $lockKey, $ttl, $stateName);
    }

    public static function consumeReserved(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        if ($ttl < 1) {
            throw new InvalidArgumentException('Reserved authentication state TTL must be positive.');
        }
        $atomic = self::assertSafe($cache);
        if ($atomic !== null) {
            return self::consumeReservedAtomically($cache, $atomic, $stateKey, $ttl, $stateName);
        }

        return self::consumeReservedWithLock($cache, $stateKey, $lockKey, $ttl, $stateName);
    }

    public static function ensureOwned(LockProviderInterface $locks, LockHandle $handle): void
    {
        if (!$locks->refresh($handle, self::LEASE_SECONDS)) {
            throw new RuntimeException('The OTP state lock was lost before mutation.');
        }
    }

    public static function reserveOnce(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        if ($ttl < 1) {
            throw new InvalidArgumentException('Reserved authentication state TTL must be positive.');
        }
        $atomic = self::assertSafe($cache);
        if ($atomic !== null) {
            return self::reserveOnceAtomically($cache, $atomic, $stateKey, $ttl, $stateName);
        }

        return self::reserveOnceWithLock($cache, $stateKey, $lockKey, $ttl, $stateName);
    }

    public static function stateAtomic(AuthenticationStateCacheInterface $cache): ?AtomicCacheInterface
    {
        $atomic = self::assertSafe($cache);
        if ($atomic === null) {
            return null;
        }

        $locks = $cache->authenticationStateLock();

        return $locks === null || self::lockRequiresAtomic($locks) ? $atomic : null;
    }

        /**
     * @template T
     * @param callable(LockProviderInterface, LockHandle): T $operation
     * @return T
     */
    public static function synchronized(
        AuthenticationStateCacheInterface $cache,
        string $key,
        callable $operation,
    ): mixed {
        self::assertLockSafe($cache);

        return self::synchronizedKnownSafe($cache, $key, $operation);
    }

    /**
     * @template T
     * @param callable(mixed): array{
     *     result:T,
     *     replacement?:mixed,
     *     ttl?:int|null,
     *     delete?:bool,
     *     failure?:string
     * } $transition
     * @return T
     */
    public static function transition(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        string $stateName,
        callable $transition,
    ): mixed {
        $atomic = self::stateAtomic($cache);
        if ($atomic !== null) {
            return self::transitionAtomically($cache, $atomic, $stateKey, $stateName, $transition);
        }

        return self::synchronizedKnownSafe(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use (
                $cache,
                $stateKey,
                $stateName,
                $transition,
            ): mixed {
                $decision = $transition($cache->get($stateKey));
                if (!array_key_exists('replacement', $decision)) {
                    return $decision['result'];
                }

                self::ensureOwned($locks, $handle);
                $mutated = ($decision['delete'] ?? false)
                    ? $cache->delete($stateKey)
                    : $cache->set($stateKey, $decision['replacement'], $decision['ttl'] ?? null);
                if (!$mutated) {
                    throw new RuntimeException(
                        $decision['failure'] ?? ('Unable to transition ' . $stateName . ' state.'),
                    );
                }

                return $decision['result'];
            },
        );
    }

    private static function advanceAtomically(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $value,
        ?int $ttl,
        string $stateName,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            $current = $cache->get($stateKey);
            if ($current === null) {
                if ($atomic->setIfAbsent($stateKey, $value, $ttl)) {
                    return true;
                }

                continue;
            }
            if (!is_int($current)) {
                throw new RuntimeException('Invalid ' . $stateName . ' state in CacheLayer.');
            }
            if ($value <= $current) {
                return false;
            }
            if ($atomic->compareAndSet($stateKey, $current, $value, $ttl)) {
                return true;
            }
        }

        throw new RuntimeException('Unable to advance ' . $stateName . ' state after atomic contention.');
    }

    private static function advanceWithLock(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $value,
        ?int $ttl,
        string $stateName,
    ): bool {
        return self::synchronizedKnownSafe(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use ($cache, $stateKey, $value, $ttl, $stateName): bool {
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

    private static function assertAuthenticationStateSafe(AuthenticationStateCacheInterface $cache): void
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
    }

    private static function atomicCapability(AuthenticationStateCacheInterface $cache): ?AtomicCacheInterface
    {
        return $cache instanceof AtomicCacheProviderInterface ? $cache->atomic() : null;
    }



    private static function consumeOnceAtomically(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $ttl,
        string $stateName,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            if ($atomic->setIfAbsent($stateKey, 1, $ttl)) {
                return true;
            }
            $current = $cache->get($stateKey);
            if ($current === 1) {
                return false;
            }
            if ($current !== null) {
                throw new RuntimeException('Invalid ' . $stateName . ' token in CacheLayer.');
            }
        }

        throw new RuntimeException('Unable to consume ' . $stateName . ' token after atomic contention.');
    }

    private static function consumeOnceWithLock(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        return self::synchronizedKnownSafe(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use ($cache, $stateKey, $ttl, $stateName): bool {
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

    private static function consumeReservedAtomically(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $ttl,
        string $stateName,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            $current = $cache->get($stateKey);
            if ($current === null || $current === 1) {
                return false;
            }
            if ($current !== 0) {
                throw new RuntimeException('Invalid ' . $stateName . ' reservation in CacheLayer.');
            }
            if ($atomic->compareAndSet($stateKey, 0, 1, $ttl)) {
                return true;
            }
        }

        throw new RuntimeException('Unable to consume reserved ' . $stateName . ' after atomic contention.');
    }

    private static function consumeReservedWithLock(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        return self::synchronizedKnownSafe(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use ($cache, $stateKey, $ttl, $stateName): bool {
                $current = $cache->get($stateKey);
                if ($current === null || $current === 1) {
                    return false;
                }
                if ($current !== 0) {
                    throw new RuntimeException('Invalid ' . $stateName . ' reservation in CacheLayer.');
                }
                self::ensureOwned($locks, $handle);
                if (!$cache->set($stateKey, 1, $ttl)) {
                    throw new RuntimeException('Unable to consume reserved ' . $stateName . '.');
                }

                return true;
            },
        );
    }

    

    private static function lockRequiresAtomic(LockProviderInterface $locks): bool
    {
        return $locks instanceof MemcachedLockProvider || $locks instanceof RedisLockProvider;
    }

    private static function reserveOnceAtomically(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $ttl,
        string $stateName,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            if ($atomic->setIfAbsent($stateKey, 0, $ttl)) {
                return true;
            }
            $current = $cache->get($stateKey);
            if ($current === 0 || $current === 1) {
                return false;
            }
            if ($current !== null) {
                throw new RuntimeException('Invalid ' . $stateName . ' reservation in CacheLayer.');
            }
        }

        throw new RuntimeException('Unable to reserve ' . $stateName . ' after atomic contention.');
    }

    private static function reserveOnceWithLock(
        AuthenticationStateCacheInterface $cache,
        string $stateKey,
        string $lockKey,
        int $ttl,
        string $stateName,
    ): bool {
        return self::synchronizedKnownSafe(
            $cache,
            $lockKey,
            function (LockProviderInterface $locks, LockHandle $handle) use ($cache, $stateKey, $ttl, $stateName): bool {
                $current = $cache->get($stateKey);
                if ($current === 0 || $current === 1) {
                    return false;
                }
                if ($current !== null) {
                    throw new RuntimeException('Invalid ' . $stateName . ' reservation in CacheLayer.');
                }
                self::ensureOwned($locks, $handle);
                if (!$cache->set($stateKey, 0, $ttl)) {
                    throw new RuntimeException('Unable to reserve ' . $stateName . '.');
                }

                return true;
            },
        );
    }

    /**
     * @template T
     * @param callable(LockProviderInterface, LockHandle): T $operation
     * @return T
     */
    private static function synchronizedKnownSafe(
        AuthenticationStateCacheInterface $cache,
        string $key,
        callable $operation,
    ): mixed {
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

/**
     * @template T
     * @param callable(mixed): array{
     *     result:T,
     *     replacement?:mixed,
     *     ttl?:int|null,
     *     delete?:bool,
     *     failure?:string
     * } $transition
     * @return T
     */
    private static function transitionAtomically(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        string $stateName,
        callable $transition,
    ): mixed {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            $current = $cache->get($stateKey);
            $decision = $transition($current);
            if (!array_key_exists('replacement', $decision)) {
                return $decision['result'];
            }

            $ttl = $decision['ttl'] ?? null;
            if ($ttl !== null && $ttl < 1) {
                throw new RuntimeException('Atomic authentication state transitions require a positive TTL.');
            }
            $mutated = $current === null
                ? $atomic->setIfAbsent($stateKey, $decision['replacement'], $ttl)
                : $atomic->compareAndSet($stateKey, $current, $decision['replacement'], $ttl);
            if ($mutated) {
                return $decision['result'];
            }
        }

        throw new RuntimeException('Unable to transition ' . $stateName . ' state after atomic contention.');
    }
}
