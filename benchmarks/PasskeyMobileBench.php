<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\MobileOTP;
use Infocyph\OTP\Passkey;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Revs;

#[BeforeMethods('setUp')]
final class PasskeyMobileBench
{
    private AuthenticationStateCacheInterface $cache;

    private MobileOTP $mobileOtp;

    private string $mobileOtpCode;

    private Passkey $passkey;

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function __construct()
    {
        $this->setUp();
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function setUp(): void
    {
        $this->cache = Cache::memory(
            'otp-passkey-mobile-bench',
            new CacheOptions(
                integrityKey: str_repeat('i', 32),
                allowClosures: false,
                allowObjects: false,
                failOpen: false,
            ),
        );
        $this->mobileOtp = new MobileOTP('7ac61d4736f51a2b', '5555');
        $this->mobileOtpCode = $this->mobileOtp->generate(1_234_567_890);
        $this->passkey = new Passkey(
            $this->cache,
            'example.com',
            ['https://example.com'],
        );
    }

    /**
     * @throws \InvalidArgumentException
     */
    public function benchMobileOtpGenerate(): void
    {
        $this->mobileOtp->generate(1_234_567_890);
    }

    /**
     * @throws \InvalidArgumentException
     */
    public function benchMobileOtpVerify(): void
    {
        $this->mobileOtp->verify($this->mobileOtpCode, 1_234_567_890);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     */
    #[Revs(1)]
    public function benchPasskeyBeginAuthentication(): void
    {
        $this->passkey->beginAuthentication('bench:passkey:auth');
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface
     * @throws \Symfony\Component\Serializer\Exception\NotNormalizableValueException
     * @throws \Symfony\Component\Serializer\Exception\UnexpectedValueException
     */
    #[Revs(1)]
    public function benchPasskeyBeginRegistration(): void
    {
        $this->passkey->beginRegistration(
            'bench:passkey:registration',
            'bench-user',
            'bench@example.com',
            'Bench User',
        );
    }
}
