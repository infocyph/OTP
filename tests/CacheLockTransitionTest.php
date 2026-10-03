<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Support\CacheLock;

test('whole-record atomic transitions retry from the winning state after contention', function () {
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
            $expectedStates[] = $expected;
            $replacementStates[] = $replacement;
            $attempt++;

            return $attempt === 2;
        });

    $result = CacheLock::transition(
        $cache,
        'state-key',
        'unused-lock-key',
        'test',
        static function (mixed $stored): array {
            expect($stored)->toBeArray();
            $next = $stored;
            $next['remaining']--;

            return [
                'result' => $next['remaining'],
                'replacement' => $next,
                'ttl' => 30,
            ];
        },
    );

    expect($result)->toBe(1)
        ->and($expectedStates)->toBe([$initial, $winner])
        ->and($replacementStates)->toBe([
            ['v' => 1, 'remaining' => 2],
            ['v' => 1, 'remaining' => 1],
        ]);
});

test('whole-record atomic transition contention is bounded and fails closed', function () {
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
            expect($stored)->toBeArray();
            $next = $stored;
            $next['remaining']--;

            return [
                'result' => false,
                'replacement' => $next,
                'ttl' => 30,
            ];
        },
    ))->toThrow(RuntimeException::class, 'after atomic contention');
});
