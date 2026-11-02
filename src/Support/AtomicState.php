<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use RuntimeException;

/** @internal Atomic persistence, bounded CAS retries and precommit cancellation. */
final class AtomicState
{
    private const int MAX_ATOMIC_ATTEMPTS = 8;

    public static function advance(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $value,
        ?int $ttl,
        string $stateName,
        ?RunwireExecutionContext $runwire,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            CacheLock::checkpoint($runwire);
            $current = $cache->get($stateKey);
            if ($current === null) {
                CacheLock::checkpoint($runwire);
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
            CacheLock::checkpoint($runwire);
            if ($atomic->compareAndSet($stateKey, $current, $value, $ttl)) {
                return true;
            }
        }

        throw new RuntimeException('Unable to advance ' . $stateName . ' state after atomic contention.');
    }

    public static function claim(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $marker,
        int $ttl,
        string $stateName,
        ?RunwireExecutionContext $runwire,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            CacheLock::checkpoint($runwire);
            if ($atomic->setIfAbsent($stateKey, $marker, $ttl)) {
                return true;
            }
            $current = $cache->get($stateKey);
            if ($current === 1 || $current === $marker) {
                return false;
            }
            if ($current !== null) {
                $kind = $marker === 0 ? ' reservation' : ' token';

                throw new RuntimeException('Invalid ' . $stateName . $kind . ' in CacheLayer.');
            }
        }

        $failure = $marker === 0
            ? 'Unable to reserve ' . $stateName
            : 'Unable to consume ' . $stateName . ' token';

        throw new RuntimeException($failure . ' after atomic contention.');
    }

    public static function consumeReserved(
        AuthenticationStateCacheInterface $cache,
        AtomicCacheInterface $atomic,
        string $stateKey,
        int $ttl,
        string $stateName,
        ?RunwireExecutionContext $runwire,
    ): bool {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            CacheLock::checkpoint($runwire);
            $current = $cache->get($stateKey);
            if ($current === null || $current === 1) {
                return false;
            }
            if ($current !== 0) {
                throw new RuntimeException('Invalid ' . $stateName . ' reservation in CacheLayer.');
            }
            CacheLock::checkpoint($runwire);
            if ($atomic->compareAndSet($stateKey, 0, 1, $ttl)) {
                return true;
            }
        }

        throw new RuntimeException('Unable to consume reserved ' . $stateName . ' after atomic contention.');
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
        AtomicCacheInterface $atomic,
        string $stateKey,
        string $stateName,
        callable $transition,
        ?RunwireExecutionContext $runwire,
    ): mixed {
        for ($attempt = 0; $attempt < self::MAX_ATOMIC_ATTEMPTS; $attempt++) {
            CacheLock::checkpoint($runwire);
            $current = $cache->get($stateKey);
            $decision = $transition($current);
            if (!array_key_exists('replacement', $decision)) {
                return $decision['result'];
            }

            $ttl = $decision['ttl'] ?? null;
            if ($ttl !== null && $ttl < 1) {
                throw new RuntimeException('Atomic authentication state transitions require a positive TTL.');
            }
            CacheLock::checkpoint($runwire);
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
