<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\VerificationReason;

test('atomic GenericOtp terminal tombstone rejects a delayed verifier with an earlier timestamp', function () {
    $state = null;
    $nestedAccepted = null;
    $triggerNestedVerifier = false;
    $otp = null;

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
    $cache->method('get')->willReturnCallback(static fn(string $key): mixed => $state);

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
        function (
            string $key,
            mixed $expected,
            mixed $replacement,
            mixed $ttl,
        ) use (&$state, &$nestedAccepted, &$triggerNestedVerifier, &$otp): bool {
            unset($key, $ttl);
            if ($triggerNestedVerifier) {
                $triggerNestedVerifier = false;
                usleep(1_100_000);
                $nestedAccepted = $otp?->verify('binding', $GLOBALS['atomicGenericCode']);
            }
            if ($state !== $expected) {
                return false;
            }

            $state = $replacement;

            return true;
        },
    );

    $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 30);
    $GLOBALS['atomicGenericCode'] = $otp->generate('binding');
    $triggerNestedVerifier = true;

    $delayedAccepted = $otp->verify('binding', $GLOBALS['atomicGenericCode']);
    unset($GLOBALS['atomicGenericCode']);

    expect($nestedAccepted)->toBeTrue()
        ->and($delayedAccepted)->toBeFalse()
        ->and($state)->toBeArray()
        ->and($state['remainingAttempts'] ?? null)->toBe(0);
});

test('atomic GridOTP attempt-exhaustion tombstone rejects a valid response from a stale timestamp', function () {
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
    $cache->method('get')->willReturnCallback(static fn(string $key): mixed => $state);

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

    expect($exhausted->matched)->toBeFalse()
        ->and($state)->toBeArray()
        ->and($state['consumed'] ?? null)->toBeTrue()
        ->and($stale->matched)->toBeFalse()
        ->and($stale->reason)->toBe(VerificationReason::Replay);
});
