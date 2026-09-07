<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\Support\CacheLock;
use PhpBench\Attributes\BeforeMethods;

#[BeforeMethods('setUp')]
final class CacheLayer33ReplayBench
{
    private AuthenticationStateCacheInterface $atomicCache;

    private int $atomicCounter = 0;

    private AuthenticationStateCacheInterface $lockCache;

    private int $lockCounter = 0;

    private string $atomicStateKey;

    private string $atomicLockKey;

    private string $lockStateKey;

    private string $lockLockKey;

    public function setUp(): void
    {
        $options = new CacheOptions(
            integrityKey: str_repeat('i', 32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        );
        $this->atomicCache = Cache::memory('otp-bench-atomic-replay', $options);
        $this->lockCache = Cache::weakMap('otp-bench-lock-replay', $options);
        $this->atomicStateKey = hash('sha256', 'otp-bench:atomic-state');
        $this->atomicLockKey = hash('sha256', 'otp-bench:atomic-lock');
        $this->lockStateKey = hash('sha256', 'otp-bench:lock-state');
        $this->lockLockKey = hash('sha256', 'otp-bench:lock-lock');
    }

    public function benchAtomicMonotonicAdvance(): void
    {
        $this->atomicCounter++;
        CacheLock::advance(
            $this->atomicCache,
            $this->atomicStateKey,
            $this->atomicLockKey,
            $this->atomicCounter,
            300,
            'benchmark replay',
        );
    }

    public function benchLockFallbackMonotonicAdvance(): void
    {
        $this->lockCounter++;
        CacheLock::advance(
            $this->lockCache,
            $this->lockStateKey,
            $this->lockLockKey,
            $this->lockCounter,
            300,
            'benchmark replay',
        );
    }

    public function benchAtomicOneTimeClaim(): void
    {
        $stateKey = hash('sha256', 'otp-bench:atomic-claim:' . $this->atomicCounter++);
        CacheLock::consumeOnce(
            $this->atomicCache,
            $stateKey,
            $this->atomicLockKey,
            300,
            'benchmark claim',
        );
    }

    public function benchLockFallbackOneTimeClaim(): void
    {
        $stateKey = hash('sha256', 'otp-bench:lock-claim:' . $this->lockCounter++);
        CacheLock::consumeOnce(
            $this->lockCache,
            $stateKey,
            $this->lockLockKey,
            300,
            'benchmark claim',
        );
    }
}
