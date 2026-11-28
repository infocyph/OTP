<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\AOTP;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Passkey;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\TOTP;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;

final class StateKeyCompatibilityTest extends TestCase
{
    /**
     * @throws \InvalidArgumentException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('TOTP keeps the v1 replay-state key')]
    public function testTOTPKeepsTheV1ReplayStateKey(): void
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
        $cache->method('get')->willReturn(null);
        $atomic->expects($this->once())->method('setIfAbsent')->with(
            '3b37a43e97fa59b71c367a7a2321d718e454126307b02b6549bb5e58521b2bfe',
            100,
            30,
        )->willReturn(true);

        $totp = new TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        expect($totp->verifyWithWindow($totp->generate(3_000), 3_000, cache: $cache, factorId: 'factor-v1')->matched)
            ->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     */
    #[TestDox('HOTP keeps the v1 replay-state key')]
    public function testHOTPKeepsTheV1ReplayStateKey(): void
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
        $cache->method('get')->willReturn(null);
        $atomic->expects($this->once())->method('setIfAbsent')->with(
            'ed3e9fa7398752a5a573b6ead0b81e9a9879fa057476cf21ab40dcd8db593439',
            0,
            null,
        )->willReturn(true);

        expect((new HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
            ->verifyWithResult('755224', 0, cache: $cache, factorId: 'factor-v1')->matched)->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \TypeError
     */
    #[TestDox('counter OCRA keeps the v1 replay-state key')]
    public function testCounterOCRAKeepsTheV1ReplayStateKey(): void
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
        $cache->method('get')->willReturn(null);
        $atomic->expects($this->once())->method('setIfAbsent')->with(
            '1920e10575738d81e851fb5f7cf474e37b92b8c10b75845d61ab5ffde6bccf83',
            0,
            null,
        )->willReturn(true);

        $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', '12345678901234567890123456789012');
        $code = $ocra->generate('12345678', 0);
        expect($ocra->verifyWithResult($code, '12345678', 0, cache: $cache, factorId: 'factor-v1')->matched)
            ->toBeTrue();
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \TypeError
     * @throws \RuntimeException
     */
    #[TestDox('non-counter OCRA keeps the v1 message replay-state key')]
    public function testNonCounterOCRAKeepsTheV1MessageReplayStateKey(): void
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
        $atomic->expects($this->once())->method('setIfAbsent')->with(
            '05736871982693a8886385eabc65c0c0bb1f63f5c0bcc6d29c68b7ab05d00503',
            1,
            300,
        )->willReturn(true);

        $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');
        expect($ocra->verifyWithResult(
            '237653',
            '00000000',
            cache: $cache,
            factorId: 'factor-v1',
            replayTtl: 300,
        )->matched)->toBeTrue();
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('GenericOtp keeps its v1 state and lock keys')]
    public function testGenericOtpKeepsItsV1StateAndLockKeys(): void
    {
        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $locks = $this->createMock(LockProviderInterface::class);
        $handle = new LockHandle(
            'de29a92d9fb4a09365b43492f7cc177e79a9c6e9b3070e1a0a327f901cc1ce91',
            'token',
        );
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn($locks);
        $locks->expects($this->once())->method('acquire')->with(
            'de29a92d9fb4a09365b43492f7cc177e79a9c6e9b3070e1a0a327f901cc1ce91',
            1.0,
            30.0,
        )->willReturn($handle);
        $locks->method('refresh')->willReturn(true);
        $locks->method('release');
        $cache->expects($this->once())->method('set')->with(
            'fa922a4eaa6817579b5c9c46517c6df43f02a07ef2653596e14ba95d1e7b1169',
            $this->callback(static fn (mixed $state): bool => is_array($state)),
            300,
        )->willReturn(true);

        expect((new GenericOtp($cache, str_repeat('g', 32)))->generate('binding-v1'))->toHaveLength(6);
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('AOTP keeps its v1 challenge state key')]
    public function testAOTPKeepsItsV1ChallengeStateKey(): void
    {
        expect(AOTP::isAvailable())->toBeTrue();

        $cache = CacheLayerState::memory();
        $keyPair = AOTP::generateKeyPair();
        $challenge = (new AOTP($keyPair->publicKey, 'https://example.com'))
            ->issue($cache, 'factor-v1', 'login', now: 1_000);
        $expectedKey = hash(
            'sha256',
            "infocyph:otp:aotp:state:v1\0factor-v1\0" . hash('sha256', $challenge->signingPayload(), true),
        );

        expect($cache->get($expectedKey))->toBe(0);
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('GridOTP keeps its v1 challenge state key')]
    public function testGridOTPKeepsItsV1ChallengeStateKey(): void
    {
        $cache = CacheLayerState::memory();
        $challenge = (new GridOTP($cache, 'ABCDEFGH'))
            ->issue('factor-v1', now: 1_000);
        $expectedKey = hash(
            'sha256',
            "infocyph:otp:gridotp:state:v1\0factor-v1\0" . $challenge->id,
        );

        expect($cache->get($expectedKey))->toBeArray();
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     * @throws \Throwable
     */
    #[TestDox('Passkey keeps its v1 ceremony state key')]
    public function testPasskeyKeepsItsV1CeremonyStateKey(): void
    {
        expect(Passkey::isAvailable())->toBeTrue();

        $cache = CacheLayerState::memory();
        $ceremony = (new Passkey($cache, 'example.com', ['https://example.com']))
            ->beginRegistration('binding-v1', 'user-handle', 'alice', 'Alice', now: 1_000);
        $expectedKey = hash(
            'sha256',
            "infocyph:otp:passkey:state:v1\0binding-v1\0" . $ceremony->id,
        );

        expect($cache->get($expectedKey))->toBeArray();
    }
}
