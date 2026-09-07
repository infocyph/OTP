<?php

declare(strict_types=1);

namespace Infocyph\OTP\Benchmarks;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\AOTP;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\ValueObjects\AotpChallenge;
use Infocyph\OTP\ValueObjects\GridChallenge;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Revs;

#[BeforeMethods('setUp')]
final class AotpGridBench
{
    private AOTP $aotp;
    private AotpChallenge $aotpChallenge;
    private AuthenticationStateCacheInterface $cache;
    private string $gridSecret;
    private GridChallenge $gridChallenge;
    private GridOTP $gridOtp;
    private string $privateKey;

    public function setUp(): void
    {
        $this->cache = Cache::memory(
            'otp-aotp-grid-bench',
            new CacheOptions(
                integrityKey: str_repeat('i', 32),
                allowClosures: false,
                allowObjects: false,
                failOpen: false,
            ),
        );
        $keys = AOTP::generateKeyPair();
        $this->privateKey = $keys->privateKey;
        $this->aotp = new AOTP($keys->publicKey, 'bench.example.com');
        $this->aotpChallenge = $this->aotp->issue($this->cache, 'bench:aotp');
        $this->gridSecret = GridOTP::generateSecret();
        $this->gridOtp = new GridOTP($this->cache, $this->gridSecret);
        $this->gridChallenge = $this->gridOtp->issue('bench:grid');
    }

    public function benchAotpSign(): void
    {
        AOTP::respond($this->privateKey, $this->aotpChallenge, 'bench.example.com');
    }

    #[Revs(1)]
    public function benchAotpRoundTrip(): void
    {
        $challenge = $this->aotp->issue($this->cache, 'bench:aotp:roundtrip');
        $response = AOTP::respond($this->privateKey, $challenge, 'bench.example.com');
        $this->aotp->verify($this->cache, 'bench:aotp:roundtrip', $challenge, $response);
    }

    public function benchGridRespond(): void
    {
        GridOTP::respond($this->gridChallenge, $this->gridSecret);
    }

    #[Revs(1)]
    public function benchGridRoundTrip(): void
    {
        $challenge = $this->gridOtp->issue('bench:grid:roundtrip');
        $response = GridOTP::respond($challenge, $this->gridSecret);
        $this->gridOtp->verify('bench:grid:roundtrip', $challenge, $response);
    }
}
