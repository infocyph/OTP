<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\VerificationReason;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;

final class AtomicTerminalStateTest extends TestCase
{
    /**
     * @throws \InvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('atomic GenericOtp terminal tombstone rejects a delayed verifier with an earlier timestamp')]
    public function testAtomicGenericOtpTerminalTombstoneRejectsADelayedVerifierWithAnEarlierTimestamp(): void
    {
        $fixture = new class {
            public mixed $state = null;
            public ?bool $nestedAccepted = null;
            public bool $triggerNestedVerifier = false;
            public ?GenericOtp $otp = null;
            public ?string $code = null;
        };

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->method('authenticationStateLock')->willReturn(null);
        $cache->method('get')->willReturnCallback(function (string $key) use ($fixture): mixed {
            unset($key);

            return $fixture->state;
        });

        $atomic->method('setIfAbsent')->willReturnCallback(
            function (string $key, mixed $value, mixed $ttl) use ($fixture): bool {
                unset($key, $ttl);
                if ($fixture->state !== null) {
                    return false;
                }

                $fixture->state = $value;

                return true;
            },
        );
        $atomic->method('compareAndSet')->willReturnCallback(
            function (
                string $key,
                mixed $expected,
                mixed $replacement,
                mixed $ttl,
            ) use ($fixture): bool {
                unset($key, $ttl);
                if ($fixture->triggerNestedVerifier) {
                    $fixture->triggerNestedVerifier = false;
                    usleep(1_100_000);
                    $fixture->nestedAccepted = ($fixture->otp ?? throw new \LogicException('Missing OTP fixture.'))->verify('binding', $fixture->code ?? throw new \LogicException('Missing code fixture.'));
                }
                if ($fixture->state !== $expected) {
                    return false;
                }

                $fixture->state = $replacement;

                return true;
            },
        );

        $fixture->otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 30);
        $fixture->code = $fixture->otp->generate('binding');
        $fixture->triggerNestedVerifier = true;

        $delayedAccepted = $fixture->otp->verify('binding', $fixture->code);

        $stored = $fixture->state;
        self::assertIsArray($stored);
        expect($fixture->nestedAccepted)->toBeTrue()
            ->and($delayedAccepted)->toBeFalse()
            ->and($fixture->state)->toBeArray()
            ->and($stored['remainingAttempts'] ?? null)->toBe(0);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    #[TestDox('atomic GridOTP attempt-exhaustion tombstone rejects a valid response from a stale timestamp')]
    public function testAtomicGridOTPAttemptExhaustionTombstoneRejectsAValidResponseFromAStaleTimestamp(): void
    {
        $state = null;

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->method('authenticationStateLock')->willReturn(null);
        $cache->method('get')->willReturnCallback(function (string $key) use (&$state): mixed {
            unset($key);

            return $state;
        });

        $atomic->method('setIfAbsent')->willReturnCallback(
            function (string $key, mixed $value, mixed $ttl) use (&$state): bool {
                unset($key, $ttl);
                if ($state !== null) {
                    return false;
                }

                $state = $value;

                return true;
            },
        );
        $atomic->method('compareAndSet')->willReturnCallback(
            function (string $key, mixed $expected, mixed $replacement, mixed $ttl) use (&$state): bool {
                unset($key, $ttl);
                if ($state !== $expected) {
                    return false;
                }

                $state = $replacement;

                return true;
            },
        );

        $secret = 'ABCDEFGH';
        $service = new GridOTP($cache, $secret, ttlSeconds: 60, maxAttempts: 1);
        $challenge = $service->issue('factor', now: 100);
        $valid = GridOTP::respond($challenge, $secret);
        $wrong = ((int) $valid[0] + 1) % 10 . substr($valid, 1);

        $exhausted = $service->verifyWithResult('factor', $challenge, $wrong, now: 120);
        $stale = $service->verifyWithResult('factor', $challenge, $valid, now: 110);

        self::assertIsArray($state);
        expect($exhausted->matched)->toBeFalse()
            ->and($state['consumed'] ?? null)->toBeTrue()
            ->and($stale->matched)->toBeFalse()
            ->and($stale->reason)->toBe(VerificationReason::Replay);
    }
}
