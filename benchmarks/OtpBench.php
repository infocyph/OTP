<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Cache\Lock\FileLockProvider;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Revs;

#[BeforeMethods('setUp')]
final class OtpBench
{
    private AuthenticationStateCacheInterface $cache;

    private string $genericCode;

    private GenericOtp $genericOtp;

    private GenericOtp $genericOtpExhausted;

    private GenericOtp $genericOtpMissing;

    private string $genericWrongCode;

    private HOTP $hotp;

    private string $hotpCode;

    private string $hotpLookAhead100Code;

    private string $hotpLookAhead25Code;

    private AuthenticationStateCacheInterface $hotpReplayCache;

    private LockProviderInterface $locks;

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

    private string $totpFuture50Code;

    private string $totpFuture5Code;

    private string $totpPast50Code;

    private string $totpPast5Code;

    private AuthenticationStateCacheInterface $totpReplayCache;

    private TOTP $totpSha1;

    private TOTP $totpSha512;

    public function setUp(): void
    {
        $options = new CacheOptions(
            integrityKey: str_repeat('i', 32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        );
        $this->cache = Cache::memory('otp-bench', $options);
        $this->locks = new FileLockProvider();
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
            $this->cache,
            str_repeat('g', 32),
            ttlSeconds: 60,
        );
        $this->genericOtpMissing = new GenericOtp($this->cache, str_repeat('g', 32));
        $this->genericOtpExhausted = new GenericOtp(
            $this->cache,
            str_repeat('g', 32),
            maxAttempts: 1,
        );
        $this->recoveryCodes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));

        $this->totpCode = $this->totp->generate(1716532624);
        $this->hotpCode = $this->hotp->generate(5);
        $this->hotpLookAhead25Code = $this->hotp->generate(25);
        $this->hotpLookAhead100Code = $this->hotp->generate(100);
        $this->ocraCode = $this->ocra->generate('12345678', 0, '1234');
        $this->genericCode = $this->genericOtp->generate($this->signature);
        $exhaustedCode = $this->genericOtpExhausted->generate('bench:exhausted');
        $this->genericWrongCode = $exhaustedCode === '000000' ? '000001' : '000000';
        $this->recoveryCode = $this->recoveryCodes->generate('bench-user')->plainCodes[0];
        $this->provisioningUri = $this->totp->getProvisioningUri('user@example.com', 'Example');
        $this->totpReplayCache = Cache::memory('otp-bench-replay', $options);
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1_716_532_624,
            cache: $this->totpReplayCache,
            factorId: 'bench-user',
        );
        $this->hotpReplayCache = Cache::memory('otp-bench-hotp-replay', $options);
        $this->hotp->verifyWithResult(
            $this->hotpCode,
            5,
            cache: $this->hotpReplayCache,
            factorId: 'bench-user',
        );
        $currentStep = $this->totp->getCurrentTimeStep(1_716_532_624);
        $this->totpPast5Code = $this->totp->generate(($currentStep - 5) * 30);
        $this->totpPast50Code = $this->totp->generate(($currentStep - 50) * 30);
        $this->totpFuture5Code = $this->totp->generate(($currentStep + 5) * 30);
        $this->totpFuture50Code = $this->totp->generate(($currentStep + 50) * 30);
    }

    public function benchCacheLayerLockRoundTrip(): void
    {
        $handle = $this->locks->acquire('benchmark-lock', 1.0, 30.0);
        $this->locks->release($handle);
    }

    public function benchCacheLayerStateRoundTrip(): void
    {
        $this->cache->set('benchmark-state', 1, 60);
        $this->cache->get('benchmark-state');
    }

    public function benchGenericOtpConstruction(): void
    {
        new GenericOtp($this->cache, str_repeat('g', 32));
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

    #[Revs(1)]
    public function benchGenericOtpVerifyExhausted(): void
    {
        $this->genericOtpExhausted->verify('bench:exhausted', $this->genericWrongCode);
    }

    #[Revs(1)]
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

    public function benchHotpReplayAccepted(): void
    {
        $cache = Cache::memory(
            'otp-bench-hotp-accept',
            new CacheOptions(integrityKey: str_repeat('i', 32), failOpen: false),
        );
        $this->hotp->verifyWithResult($this->hotpCode, 5, cache: $cache, factorId: 'bench-user');
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
        $this->hotp->verify($this->hotpLookAhead100Code, 0, 100);
    }

    public function benchHotpVerifyLookAhead25(): void
    {
        $this->hotp->verify($this->hotpLookAhead25Code, 0, 25);
    }

    public function benchHotpVerifyReplay(): void
    {
        $this->hotp->verifyWithResult(
            $this->hotpCode,
            5,
            cache: $this->hotpReplayCache,
            factorId: 'bench-user',
        );
    }

    public function benchOcraChallengeConsume(): void
    {
        $cache = Cache::memory(
            'otp-bench-ocra',
            new CacheOptions(integrityKey: str_repeat('i', 32), failOpen: false),
        );
        $code = $this->ocraChallenge->generate('12345678');
        $this->ocraChallenge->verifyWithResult(
            $code,
            '12345678',
            cache: $cache,
            factorId: 'bench-user',
            replayTtl: 300,
        );
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

    public function benchTotpVerifyFuture5(): void
    {
        $this->totp->verifyWithWindow($this->totpFuture5Code, 1_716_532_624, new VerificationWindow(0, 5));
    }

    public function benchTotpVerifyFuture50(): void
    {
        $this->totp->verifyWithWindow($this->totpFuture50Code, 1_716_532_624, new VerificationWindow(0, 50));
    }

    public function benchTotpVerifyInvalid(): void
    {
        $this->totp->verify('000000', 1716532624, 1, 1);
    }

    public function benchTotpVerifyMalformed(): void
    {
        $this->totp->verify('invalid', 1716532624, 1, 1);
    }

    public function benchTotpVerifyPast5(): void
    {
        $this->totp->verifyWithWindow($this->totpPast5Code, 1_716_532_624, new VerificationWindow(5));
    }

    public function benchTotpVerifyPast50(): void
    {
        $this->totp->verifyWithWindow($this->totpPast50Code, 1_716_532_624, new VerificationWindow(50));
    }

    public function benchTotpVerifyReplayAccepted(): void
    {
        $cache = Cache::memory(
            'otp-bench-totp',
            new CacheOptions(integrityKey: str_repeat('i', 32), failOpen: false),
        );
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1716532624,
            cache: $cache,
            factorId: 'bench-user',
        );
    }

    public function benchTotpVerifyReplayRejected(): void
    {
        $this->totp->verifyWithWindow(
            $this->totpCode,
            1716532624,
            cache: $this->totpReplayCache,
            factorId: 'bench-user',
        );
    }

    public function benchTotpVerifyWindow0(): void
    {
        $this->totp->verifyWithWindow($this->totpCode, 1_716_532_624, new VerificationWindow());
    }
}
