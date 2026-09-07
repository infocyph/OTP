<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\Support\CacheLock;
use PhpBench\Attributes\BeforeMethods;
use RuntimeException;

#[BeforeMethods('setUp')]
final class CacheLayer33ReplayBench
{
    private Cache $atomicCache;

    private string $atomicCasKey;

    private int $atomicCasValue = 0;

    private int $atomicCounter = 0;

    private string $atomicLockKey;

    private AtomicCacheInterface $atomicOperations;

    private string $atomicStateKey;

    private Cache $lockCache;

    private int $lockCounter = 0;

    private string $lockLockKey;

    private string $lockStateKey;

    public function setUp(): void
    {
        $options = new CacheOptions(
            integrityKey: str_repeat('i', 32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        );
        $this->atomicCache = Cache::memory('otp-bench-atomic-replay', $options);
        $this->atomicCache->clear();
        $this->atomicOperations = $this->atomicCache->atomic()
            ?? throw new RuntimeException('The benchmark atomic backend does not expose CacheLayer atomics.');

        $this->lockCache = Cache::file(
            'otp-bench-lock-replay',
            sys_get_temp_dir() . '/infocyph-otp-cachelayer33-bench',
            $options,
        );
        $this->lockCache->clear();

        $this->atomicCounter = 0;
        $this->atomicCasValue = 0;
        $this->lockCounter = 0;
        $this->atomicStateKey = hash('sha256', 'otp-bench:atomic-state');
        $this->atomicCasKey = hash('sha256', 'otp-bench:atomic-cas');
        $this->atomicLockKey = hash('sha256', 'otp-bench:atomic-lock');
        $this->lockStateKey = hash('sha256', 'otp-bench:lock-state');
        $this->lockLockKey = hash('sha256', 'otp-bench:lock-lock');
        if (!$this->atomicOperations->setIfAbsent($this->atomicCasKey, 0, 300)) {
            throw new RuntimeException('Unable to initialize the atomic CAS benchmark state.');
        }
    }

    public function benchAtomicCompareAndSet(): void
    {
        $next = $this->atomicCasValue + 1;
        if (!$this->atomicOperations->compareAndSet(
            $this->atomicCasKey,
            $this->atomicCasValue,
            $next,
            300,
        )) {
            throw new RuntimeException('Atomic CAS benchmark state unexpectedly diverged.');
        }
        $this->atomicCasValue = $next;
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

    public function benchAtomicSetIfAbsent(): void
    {
        $stateKey = hash('sha256', 'otp-bench:atomic-direct-claim:' . $this->atomicCounter++);
        $this->atomicOperations->setIfAbsent($stateKey, 1, 300);
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
