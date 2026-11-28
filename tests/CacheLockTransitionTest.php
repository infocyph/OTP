<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CacheLockTransitionTest extends TestCase
{
    /**
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('whole-record atomic transitions retry from the winning state after contention')]
    public function testWholeRecordAtomicTransitionsRetryFromTheWinningStateAfterContention(): void
    {
        $initial = ['v' => 1, 'remaining' => 3];
        $winner = ['v' => 1, 'remaining' => 2];
        $expectedStates = [];
        $replacementStates = [];
        $attempt = 0;

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->expects($this->once())->method('authenticationStateLock')->willReturn(null);
        $cache->expects($this->exactly(2))->method('get')
            ->with('state-key')
            ->willReturnOnConsecutiveCalls($initial, $winner);
        $cache->expects($this->never())->method('set');
        $cache->expects($this->never())->method('delete');

        $atomic->expects($this->exactly(2))->method('compareAndSet')
            ->willReturnCallback(function (
                string $key,
                mixed $expected,
                mixed $replacement,
                mixed $ttl,
            ) use (&$attempt, &$expectedStates, &$replacementStates): bool {
                expect($key)->toBe('state-key')
                    ->and($ttl)->toBe(30);
                self::assertIsArray($expected);
                self::assertIsArray($replacement);
                $expectedStates[] = $expected;
                $replacementStates[] = $replacement;
                $attempt++;

                return $attempt === 2;
            });

        self::assertSame(1, CacheLock::transition(
            $cache,
            'state-key',
            'unused-lock-key',
            'test',
            static function (mixed $stored): array {
                if (!is_array($stored) || !isset($stored['remaining']) || !is_int($stored['remaining'])) {
                    throw new RuntimeException('Invalid test state.');
                }
                $next = $stored;
                $remaining = $stored['remaining'] - 1;
                $next['remaining'] = $remaining;

                return [
                    'result' => $remaining,
                    'replacement' => $next,
                    'ttl' => 30,
                ];
            },
        ));

        expect($expectedStates)->toBe([$initial, $winner])
            ->and($replacementStates)->toBe([
                ['v' => 1, 'remaining' => 2],
                ['v' => 1, 'remaining' => 1],
            ]);
    }

    #[TestDox('whole-record atomic transition contention is bounded and fails closed')]
    public function testWholeRecordAtomicTransitionContentionIsBoundedAndFailsClosed(): void
    {
        $state = ['v' => 1, 'remaining' => 3];
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->expects($this->once())->method('authenticationStateLock')->willReturn(null);
        $cache->expects($this->exactly(8))->method('get')->with('state-key')->willReturn($state);
        $atomic->expects($this->exactly(8))->method('compareAndSet')->willReturn(false);

        expect(fn () => CacheLock::transition(
            $cache,
            'state-key',
            'unused-lock-key',
            'test',
            static function (mixed $stored): array {
                if (!is_array($stored) || !isset($stored['remaining']) || !is_int($stored['remaining'])) {
                    throw new RuntimeException('Invalid test state.');
                }
                $next = $stored;
                $remaining = $stored['remaining'] - 1;
                $next['remaining'] = $remaining;

                return [
                    'result' => false,
                    'replacement' => $next,
                    'ttl' => 30,
                ];
            },
        ))->toThrow(RuntimeException::class, 'after atomic contention');
    }
    /**
     * @throws \Throwable
     */
    #[TestDox('SQLite uses its effective coordinated lock for whole records and retains native scalar atomics')]
    public function testSqliteUsesEffectiveCoordinatedLockForWholeRecords(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'otp-capability-');
        if ($path === false) {
            throw new RuntimeException('Unable to allocate SQLite test database.');
        }

        try {
            $cache = CacheLayerState::sqlite($path);
            expect(CacheLock::stateAtomic($cache))->toBeNull()
                ->and(CacheLock::assertSafe($cache))->toBeInstanceOf(AtomicCacheInterface::class);
        } finally {
            unlink($path);
        }
    }
}
