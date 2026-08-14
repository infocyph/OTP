<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryOtpStore;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Revs;

#[BeforeMethods('setUp')]
final class OtpBench
{
    private string $genericCode;

    private GenericOtp $genericOtp;

    private GenericOtp $genericOtpMissing;

    private HOTP $hotp;

    private string $hotpCode;

    private OCRA $ocra;

    private OCRA $ocraChallenge;

    private string $ocraCode;

    private OCRA $ocraFullHmac;

    private OCRA $ocraMutual;

    private OCRA $ocraSession;

    private OCRA $ocraTime;

    private string $provisioningUri;

    private string $recoveryCode;

    private RecoveryCodes $recoveryCodes;

    private string $secret;

    private string $signature = 'bench:user@example.com';

    private TOTP $totp;

    private string $totpCode;

    private InMemoryReplayStore $totpReplayStore;

    private TOTP $totpSha1;

    private TOTP $totpSha512;

    public function setUp(): void
    {
        $this->secret = 'DZJCKBRRJVSXNTALRREMD6ZCCMNEBP53Q424XLMVN6AOL6MCNIEUGK54OEQVXQXHQFGI3UHBBSLNXUYHW2QQNV2BLZD2QNOKTRL3WSI';
        $this->totp = new TOTP($this->secret, algorithm: 'sha256');
        $this->totpSha1 = new TOTP($this->secret);
        $this->totpSha512 = new TOTP($this->secret, algorithm: 'sha512');

        $this->hotp = new HOTP(
            'GFZKEJSFNDSEZGG7K4C3UEYRWDF76LL5HD4HT73SDD6AE5EVRRH4OYPKIITGRH3MI2JUFZQX2GJNG66FPEEJIHYFP736JVONA5M7J4A',
        );

        $this->ocra = new OCRA(
            'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
            '12345678901234567890123456789012',
        );
        $this->ocraChallenge = new OCRA('OCRA-1:HOTP-SHA256-8:QN08', '12345678901234567890123456789012');
        $this->ocraFullHmac = new OCRA('OCRA-1:HOTP-SHA256-0:QN08', '12345678901234567890123456789012');
        $this->ocraMutual = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', '12345678901234567890123456789012');
        $this->ocraSession = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', '12345678901234567890123456789012');
        $this->ocraTime = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-T1M', '12345678901234567890123456789012');
        $this->genericOtp = new GenericOtp(
            new InMemoryOtpStore(),
            str_repeat('g', 32),
            ttlSeconds: 60,
        );
        $this->genericOtpMissing = new GenericOtp(new InMemoryOtpStore(), str_repeat('g', 32));
        $this->recoveryCodes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));

        $this->totpCode = $this->totp->generate(1716532624);
        $this->hotpCode = $this->hotp->generate(5);
        $this->ocraCode = $this->ocra->generate('12345678', 0, '1234');
        $this->genericCode = $this->genericOtp->generate($this->signature);
        $this->recoveryCode = $this->recoveryCodes->generate('bench-user')->plainCodes[0];
        $this->provisioningUri = $this->totp->getProvisioningUri('user@example.com', 'Example');
        $this->totpReplayStore = new InMemoryReplayStore();
        $this->totpReplayStore->advance(
            'totp:last_timestep',
            'bench-user',
            $this->totp->getCurrentTimeStep(1716532624),
            90,
        );
    }

    public function benchGenericOtpConstruction(): void
    {
        new GenericOtp(new InMemoryOtpStore(), str_repeat('g', 32));
    }

    public function benchGenericOtpGenerate(): void
    {
        $this->genericOtpMissing->generate('bench:another@example.com');
    }

    #[Revs(1)]
    public function benchGenericOtpVerify(): void
    {
        $this->genericOtp->verify($this->signature, $this->genericCode);
    }

    public function benchGenericOtpVerifyFailedAttempt(): void
    {
        $this->genericOtp->verify($this->signature, '000000');
    }

    public function benchGenericOtpVerifyMalformed(): void
    {
        $this->genericOtp->verify($this->signature, 'invalid');
    }

    public function benchGenericOtpVerifyMissing(): void
    {
        $this->genericOtpMissing->verify('missing', '000000');
    }

    public function benchHotpGenerate(): void
    {
        $this->hotp->generate(5);
    }

    public function benchHotpVerify(): void
    {
        $this->hotp->verify($this->hotpCode, 5, 3);
    }

    public function benchHotpVerifyInvalid(): void
    {
        $this->hotp->verify('000000', 5, 3);
    }

    public function benchHotpVerifyLookAhead0(): void
    {
        $this->hotp->verify($this->hotpCode, 5);
    }

    public function benchHotpVerifyLookAhead100(): void
    {
        $this->hotp->verify($this->hotpCode, 0, 100);
    }

    public function benchHotpVerifyLookAhead25(): void
    {
        $this->hotp->verify($this->hotpCode, 0, 25);
    }

    public function benchHotpVerifyReplay(): void
    {
        $store = new InMemoryReplayStore();
        $store->advance('hotp:last_counter', 'bench-user', 5);
        $this->hotp->verifyWithResult($this->hotpCode, 5, replayStore: $store, factorId: 'bench-user');
    }

    public function benchOcraGenerate(): void
    {
        $this->ocra->generate('12345678', 0, '1234');
    }

    public function benchOcraGenerateChallenge(): void
    {
        $this->ocraChallenge->generate('12345678');
    }

    public function benchOcraGenerateCounter(): void
    {
        $this->ocra->generate('12345678', 0, '1234');
    }

    public function benchOcraGenerateFullHmac(): void
    {
        $this->ocraFullHmac->generateSignature('12345678');
    }

    public function benchOcraGenerateMutual(): void
    {
        $this->ocraMutual->generateMutual('CLI22220', 'SRV11110');
    }

    public function benchOcraGeneratePin(): void
    {
        $this->ocra->generate('12345678', 0, '1234');
    }

    public function benchOcraGenerateSession(): void
    {
        $this->ocraSession->generate('12345678', session: 'session-data');
    }

    public function benchOcraGenerateTime(): void
    {
        $this->ocraTime->generate('12345678', timestamp: 1_716_532_624);
    }

    public function benchOcraVerify(): void
    {
        $this->ocra->verify($this->ocraCode, '12345678', 0, '1234');
    }

    public function benchOcraVerifyInvalid(): void
    {
        $this->ocra->verify('00000000', '12345678', 0, '1234');
    }

    public function benchProvisioningEnrollmentPayload(): void
    {
        $this->totp->getEnrollmentPayload('user@example.com', 'Example');
    }

    #[Revs(1)]
    public function benchProvisioningSvgRender(): void
    {
        $this->totp->getProvisioningUriQR('user@example.com', 'Example');
    }

    public function benchProvisioningUriBuild(): void
    {
        $this->totp->getProvisioningUri('user@example.com', 'Example');
    }

    public function benchProvisioningUriParse(): void
    {
        ProvisioningUriParser::parse($this->provisioningUri);
    }

    #[Revs(1)]
    public function benchRecoveryConsume(): void
    {
        $this->recoveryCodes->consume('bench-user', $this->recoveryCode);
    }

    public function benchRecoveryConsumeInvalid(): void
    {
        $this->recoveryCodes->consume('bench-user', 'invalid!');
    }

    #[Revs(1)]
    public function benchRecoveryGenerate(): void
    {
        $this->recoveryCodes->generate('bench-user');
    }

    #[Revs(1)]
    public function benchRecoveryGenerate100(): void
    {
        $this->recoveryCodes->generate('bench-user-100', count: 100);
    }

    public function benchSecretCanonicalValidation(): void
    {
        SecretUtility::requireStrongBase32($this->secret);
    }

    public function benchSecretDecode(): void
    {
        SecretUtility::decodeBase32($this->secret);
    }

    public function benchSecretGeneration(): void
    {
        SecretUtility::generate();
    }

    public function benchSecretNormalize(): void
    {
        SecretUtility::normalizeBase32($this->secret);
    }

    public function benchTotpGenerate(): void
    {
        $this->totp->generate(1716532624);
    }

    public function benchTotpGenerateSha1(): void
    {
        $this->totpSha1->generate(1_716_532_624);
    }

    public function benchTotpGenerateSha256(): void
    {
        $this->totp->generate(1_716_532_624);
    }

    public function benchTotpGenerateSha512(): void
    {
        $this->totpSha512->generate(1_716_532_624);
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
            factorId: 'bench-user',
        );
    }

    public function benchTotpVerifyReplayRejected(): void
    {
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1716532624,
            replayStore: $this->totpReplayStore,
            factorId: 'bench-user',
        );
    }

    public function benchTotpVerifyWindow0(): void
    {
        $this->totp->verifyWithWindow($this->totpCode, 1_716_532_624, new VerificationWindow());
    }

    public function benchTotpVerifyWindow5(): void
    {
        $this->totp->verifyWithWindow($this->totpCode, 1_716_532_624, new VerificationWindow(5, 5));
    }

    public function benchTotpVerifyWindow50(): void
    {
        $this->totp->verifyWithWindow($this->totpCode, 1_716_532_624, new VerificationWindow(50, 50));
    }
}
