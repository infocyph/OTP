<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\OTP;
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\Tests\Support\InMemoryCacheItemPool;
use Infocyph\OTP\TOTP;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Revs;

#[BeforeMethods('setUp')]
final class OtpBench
{
    private string $genericCode;

    private OTP $genericOtp;

    private HOTP $hotp;

    private string $hotpCode;

    private OCRA $ocra;

    private string $ocraCode;

    private string $signature = 'bench:user@example.com';

    private TOTP $totp;

    private string $totpCode;

    private InMemoryReplayStore $totpReplayStore;

    public function setUp(): void
    {
        $this->totp = (new TOTP(
            'DZJCKBRRJVSXNTALRREMD6ZCCMNEBP53Q424XLMVN6AOL6MCNIEUGK54OEQVXQXHQFGI3UHBBSLNXUYHW2QQNV2BLZD2QNOKTRL3WSI',
        ))->setAlgorithm('sha256');

        $this->hotp = (new HOTP(
            'GFZKEJSFNDSEZGG7K4C3UEYRWDF76LL5HD4HT73SDD6AE5EVRRH4OYPKIITGRH3MI2JUFZQX2GJNG66FPEEJIHYFP736JVONA5M7J4A',
        ))->setAlgorithm('sha1');

        $this->ocra = new OCRA(
            'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
            '12345678901234567890123456789012',
        );
        $this->ocra->setPin('1234');

        $this->genericOtp = new OTP(
            digitCount: 6,
            validUpto: 60,
            retry: 3,
            hashAlgorithm: 'sha256',
            cacheAdapter: new InMemoryCacheItemPool(),
        );

        $this->totpCode = $this->totp->getOTP(1716532624);
        $this->hotpCode = $this->hotp->getOTP(5);
        $this->ocraCode = $this->ocra->generate('12345678', 0);
        $this->genericCode = $this->genericOtp->generate($this->signature);
        $this->totpReplayStore = new InMemoryReplayStore();
        $this->totpReplayStore->consumeOnce(
            'totp:step',
            'bench-user',
            (string) $this->totp->getCurrentTimeStep(1716532624),
            90,
        );
    }

    public function benchGenericOtpGenerate(): void
    {
        $otp = new OTP(
            digitCount: 6,
            validUpto: 60,
            retry: 3,
            hashAlgorithm: 'sha256',
            cacheAdapter: new InMemoryCacheItemPool(),
        );

        $otp->generate('bench:another@example.com');
    }

    #[Revs(1)]
    public function benchGenericOtpVerify(): void
    {
        $this->genericOtp->verify($this->signature, $this->genericCode);
    }

    public function benchGenericOtpVerifyMalformed(): void
    {
        $this->genericOtp->verify($this->signature, 'invalid');
    }

    public function benchHotpGenerate(): void
    {
        $this->hotp->getOTP(5);
    }

    public function benchHotpVerify(): void
    {
        $this->hotp->verify($this->hotpCode, 5, 3);
    }

    public function benchHotpVerifyInvalid(): void
    {
        $this->hotp->verify('000000', 5, 3);
    }

    public function benchOcraGenerate(): void
    {
        $this->ocra->generate('12345678', 0);
    }

    public function benchOcraVerify(): void
    {
        $this->ocra->verify($this->ocraCode, '12345678', 0);
    }

    public function benchOcraVerifyInvalid(): void
    {
        $this->ocra->verify('00000000', '12345678', 0);
    }

    public function benchTotpGenerate(): void
    {
        $this->totp->getOTP(1716532624);
    }

    public function benchTotpVerify(): void
    {
        $this->totp->verify($this->totpCode, 1716532624, 1, 1);
    }

    public function benchTotpVerifyInvalid(): void
    {
        $this->totp->verify('000000', 1716532624, 1, 1);
    }

    public function benchTotpVerifyMalformed(): void
    {
        $this->totp->verify('invalid', 1716532624, 1, 1);
    }

    public function benchTotpVerifyReplayAccepted(): void
    {
        $store = new InMemoryReplayStore();
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1716532624,
            replayStore: $store,
            binding: 'bench-user',
        );
    }

    public function benchTotpVerifyReplayRejected(): void
    {
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1716532624,
            replayStore: $this->totpReplayStore,
            binding: 'bench-user',
        );
    }
}
