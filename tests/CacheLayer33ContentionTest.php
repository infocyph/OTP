<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\PdoLockProvider;
use Infocyph\CacheLayer\Exceptions\CacheBackendException;
use Infocyph\OTP\Support\AtomicState;
use Infocyph\OTP\TOTP;
use InvalidArgumentException;
use PDO;
use PDOException;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CacheLayer33ContentionTest extends TestCase
{
    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('atomic replay contention is bounded and fails closed')]
    public function testAtomicReplayContentionIsBoundedAndFailsClosed(): void
    {
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
        $cache->expects($this->exactly(8))->method('get')->willReturn(99);
        $atomic->expects($this->exactly(8))->method('compareAndSet')->willReturn(false);

        $totp = new TOTP(TOTP::generateSecret(), period: 30);

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'atomic-contention',
        ))->toThrow(RuntimeException::class, 'after atomic contention');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('replay protection rejects a cache with neither atomics nor a coordinated lock')]
    public function testReplayProtectionRejectsACacheWithNeitherAtomicsNorACoordinatedLock(): void
    {
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn(null);

        $totp = new TOTP(TOTP::generateSecret(), period: 30);

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'missing-capability',
        ))->toThrow(InvalidArgumentException::class, 'atomic or coordinated lock capability');
    }

    /**
     * @throws \Infocyph\CacheLayer\Cache\Lock\UnsupportedPdoLockDriver
     * @throws \PDOException
     * @throws \RuntimeException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \LogicException
     */
    #[TestDox('a rolled-back PDO insert observes the winning replay marker')]
    public function testRolledBackPdoInsertObservesWinner(): void
    {
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->once())->method('setIfAbsent')->willThrowException(self::deadlock());
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->expects($this->once())->method('authenticationStateLock')
            ->willReturn(new PdoLockProvider(new PDO('sqlite::memory:')));
        $cache->expects($this->once())->method('get')->with('state')->willReturn(1);
        $cache->expects($this->never())->method('set');
        $cache->expects($this->never())->method('delete');

        expect(AtomicState::claim($cache, $atomic, 'state', 1, 30, 'test', null))->toBeFalse();
    }

    /**
     * @throws \Infocyph\CacheLayer\Cache\Lock\UnsupportedPdoLockDriver
     * @throws \PDOException
     */
    #[TestDox('confirmed PDO deadlocks cannot exceed the existing atomic attempt budget')]
    public function testPdoDeadlockRetryIsBounded(): void
    {
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->exactly(8))->method('setIfAbsent')->willThrowException(self::deadlock());
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->expects($this->exactly(8))->method('authenticationStateLock')
            ->willReturn(new PdoLockProvider(new PDO('sqlite::memory:')));
        $cache->expects($this->exactly(8))->method('get')->willReturn(null);
        $cache->expects($this->never())->method('set');

        expect(fn () => AtomicState::claim($cache, $atomic, 'state', 1, 30, 'test', null))
            ->toThrow(RuntimeException::class, 'after atomic contention');
    }

    #[TestDox('ambiguous commit failure propagates without retry or lock fallback')]
    public function testAmbiguousCommitFailurePropagates(): void
    {
        $cause = new PDOException('Connection lost');
        $cause->errorInfo = ['HY000', 2013, 'Connection lost'];
        $failure = new CacheBackendException('Unknown commit outcome', 0, $cause);
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->once())->method('setIfAbsent')->willThrowException($failure);
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->expects($this->never())->method('authenticationStateLock');
        $cache->expects($this->never())->method('get');
        $cache->expects($this->never())->method('set');

        expect(fn () => AtomicState::claim($cache, $atomic, 'state', 1, 30, 'test', null))
            ->toThrow(CacheBackendException::class, 'Unknown commit outcome');
    }

    private static function deadlock(): CacheBackendException
    {
        $cause = new PDOException('Deadlock');
        $cause->errorInfo = ['40001', 1213, 'Deadlock'];

        return new CacheBackendException('Cache backend operation failed.', 0, $cause);
    }
}
