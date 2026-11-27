<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CacheLayer33FallbackSafetyTest extends TestCase
{
    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    #[TestDox('atomic provider returning null falls back to the coordinated lock path')]
    public function testAtomicProviderReturningNullFallsBackToTheCoordinatedLockPath(): void
    {
        $locks = $this->createMock(LockProviderInterface::class);
        $handle = new LockHandle('lock-key', 'token');
        $locks->expects($this->once())->method('acquire')->willReturn($handle);
        $locks->expects($this->once())->method('refresh')->with($handle, 30.0)->willReturn(true);
        $locks->expects($this->once())->method('release')->with($handle);

        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->expects($this->exactly(2))->method('atomic')->willReturn(null);
        $cache->expects($this->atLeastOnce())->method('authenticationStateLock')->willReturn($locks);
        $cache->expects($this->once())->method('get')->willReturn(null);
        $cache->expects($this->once())->method('set')->with(
            $this->callback(static fn (string $key): bool => strlen($key) === 64),
            100,
            30,
        )->willReturn(true);

        $totp = new TOTP(TOTP::generateSecret(), period: 30);

        expect($totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'lock-fallback',
        )->matched)->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('available atomic capability failures never fall back to locks')]
    public function testAvailableAtomicCapabilityFailuresNeverFallBackToLocks(): void
    {
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->once())->method('setIfAbsent')->willThrowException(
            new RuntimeException('atomic backend unavailable'),
        );

        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->expects($this->never())->method('authenticationStateLock');
        $cache->expects($this->once())->method('get')->willReturn(null);

        $totp = new TOTP(TOTP::generateSecret(), period: 30);

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'atomic-failure',
        ))->toThrow(RuntimeException::class, 'atomic backend unavailable');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('authentication replay state always requires fail-closed policy')]
    public function testAuthenticationReplayStateAlwaysRequiresFailClosedPolicy(): void
    {
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->method('isFailOpen')->willReturn(true);

        $totp = new TOTP(TOTP::generateSecret());

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'fail-open',
        ))->toThrow(InvalidArgumentException::class, 'configured fail-closed');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('authentication replay state always requires payload integrity')]
    public function testAuthenticationReplayStateAlwaysRequiresPayloadIntegrity(): void
    {
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(false);

        $totp = new TOTP(TOTP::generateSecret());

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'unsigned',
        ))->toThrow(InvalidArgumentException::class, 'enable payload integrity');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \Exception
     * @throws \TypeError
     */
    #[TestDox('authentication replay state always requires one authoritative backend')]
    public function testAuthenticationReplayStateAlwaysRequiresOneAuthoritativeBackend(): void
    {
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(false);

        $totp = new TOTP(TOTP::generateSecret());

        expect(fn () => $totp->verifyWithWindow(
            $totp->generate(3000),
            3000,
            cache: $cache,
            factorId: 'non-authoritative',
        ))->toThrow(InvalidArgumentException::class, 'one authoritative direct backend');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \TypeError
     */
    #[TestDox('one-time OCRA atomic contention is bounded and fails closed')]
    public function testOneTimeOCRAAtomicContentionIsBoundedAndFailsClosed(): void
    {
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->exactly(8))->method('setIfAbsent')->willReturn(false);

        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->expects($this->never())->method('authenticationStateLock');
        $cache->expects($this->exactly(8))->method('get')->willReturn(null);

        $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');

        expect(fn () => $ocra->verifyWithResult(
            '237653',
            '00000000',
            cache: $cache,
            factorId: 'ocra-contention',
            replayTtl: 300,
        ))->toThrow(RuntimeException::class, 'after atomic contention');
    }
}
