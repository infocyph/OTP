<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
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
     * @throws \Throwable
     */
    #[TestDox('atomic GenericOtp rechecks absolute expiry after a concurrent state transition')]
    public function testAtomicGenericOtpRechecksExpiryAfterContention(): void
    {
        $key = str_repeat('g', 32);
        $state = [
            'v' => 1,
            'digest' => hash_hmac('sha256', "generic-otp\0" . 'challenge' . "\0" . '123456', $key),
            'remainingAttempts' => 3,
            'expiresAt' => 0,
        ];
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
        $cache->expects($this->exactly(2))->method('get')->willReturnCallback(static function () use (&$state): array {
            if ($state['expiresAt'] === 0) {
                $state['expiresAt'] = time() + 1;
            }

            return $state;
        });
        $atomic->expects($this->never())->method('setIfAbsent');
        $atomic->expects($this->exactly(2))->method('compareAndSet')->willReturnCallback(
            static function (string $cacheKey, mixed $expected, mixed $replacement, mixed $ttl) use (&$state): bool {
                unset($cacheKey, $expected, $replacement, $ttl);
                if ($state['remainingAttempts'] === 3) {
                    $state['remainingAttempts'] = 2;
                    sleep(1);

                    return false;
                }

                return true;
            },
        );

        expect((new GenericOtp($cache, $key))->verify('challenge', '123456'))->toBeFalse();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
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

                self::assertIsArray($value);
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

                self::assertIsArray($replacement);
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

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('GridOTP rejects a correct response after its cached deadline passes during state access')]
    public function testGridOtpRechecksImplicitClockAfterStateAccess(): void
    {
        $secret = 'ABCDEFGH';
        $challenge = new GridOTP(CacheLayerState::memory(), $secret)->issue('factor');
        $response = GridOTP::respond($challenge, $secret);
        $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
        $cache->expects($this->once())->method('get')->willReturnCallback(static function () use ($challenge): array {
            $expiresAt = time() + 1;
            sleep(1);

            return [
                'v' => 1,
                'digest' => hash('sha256', $challenge->canonicalPayload()),
                'remainingAttempts' => 3,
                'expiresAt' => $expiresAt,
                'consumed' => false,
            ];
        });
        $cache->expects($this->once())->method('delete')->willReturn(true);
        $cache->expects($this->never())->method('set');

        expect(new GridOTP($cache, $secret)->verifyWithResult('factor', $challenge, $response)->reason)
            ->toBe(VerificationReason::Mismatch);
    }
}
