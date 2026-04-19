<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Exception;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;

final readonly class OTP
{
    /**
     * Constructor for the class.
     *
     * @param int $digitCount The number of digits.
     * @param int $validUpto The number of seconds until the code expires.
     */
    public function __construct(
        private int $digitCount = 6,
        private int $validUpto = 30,
        private int $retry = 3,
        private string $hashAlgorithm = 'xxh128',
        private ?CacheItemPoolInterface $cacheAdapter = null,
    ) {}

    /**
     * Deletes an OTP based on the given signature.
     *
     * @param string $signature The signature of the item to be deleted.
     * @return bool True if the item was successfully deleted, false otherwise.
     *
     * @throws InvalidArgumentException
     */
    public function delete(string $signature): bool
    {
        return $this->getCacheAdapter()->deleteItem('ao-otp_' . hash('xxh3', $signature));
    }

    /**
     * Flushes all the OTPs.
     */
    public function flush(): bool
    {
        return $this->getCacheAdapter()->clear();
    }

    /**
     * Generates an OTP and saves it in the cache.
     *
     * @param string $signature The signature to generate the OTP for.
     * @return string The generated OTP.
     *
     * @throws InvalidArgumentException|Exception
     */
    public function generate(string $signature): string
    {
        $this->validateRequirements();
        $otpAdapter = $this->getCacheAdapter()->getItem('ao-otp_' . hash('xxh3', $signature));
        $otp = $this->number($this->digitCount);
        $this->storeData($otpAdapter, hash($this->hashAlgorithm, $otp), $this->retry, $this->validUpto);

        return $otp;
    }

    /**
     * Verifies the given signature and OTP.
     *
     * @param string $signature The signature to be verified.
     * @param string $otp The one-time password (OTP) to be verified.
     * @param bool $deleteIfFound Whether to delete the OTP from the cache if found (disregarding verification).
     * @return bool Returns true if the signature and OTP are verified successfully, false otherwise.
     *
     * @throws InvalidArgumentException
     */
    public function verify(string $signature, string $otp, bool $deleteIfFound = true): bool
    {
        if (!preg_match('/^\d+$/', $otp) || strlen($otp) !== $this->digitCount) {
            return false;
        }
        $signature = 'ao-otp_' . hash('xxh3', $signature);
        $cacheAdapter = $this->getCacheAdapter();
        $otpAdapter = $cacheAdapter->getItem($signature);
        if (!$otpAdapter->isHit()) {
            return false;
        }
        $payload = $otpAdapter->get();
        if (
            !is_array($payload)
            || !isset($payload['secret'], $payload['retry'], $payload['expiresAt'])
            || !is_string($payload['secret'])
            || !is_int($payload['retry'])
            || !is_int($payload['expiresAt'])
        ) {
            return false;
        }

        $secret = $payload['secret'];
        $retry = $payload['retry'];
        $expiresAt = $payload['expiresAt'];
        $isVerified = hash_equals($secret, hash($this->hashAlgorithm, $otp));
        match (true) {
            $deleteIfFound || $isVerified || $retry < 1 => $cacheAdapter->deleteItem($signature),
            default => $this->storeData($otpAdapter, $secret, --$retry, $expiresAt - time()),
        };

        return $isVerified;
    }

    /**
     * @throws Exception
     */
    private function getCacheAdapter(): CacheItemPoolInterface
    {
        return $this->cacheAdapter ?? throw new Exception(
            'A PSR-6 cache pool implementation is required for generic OTP storage.',
        );
    }

    /**
     * Generate Secure random number of given length
     *
     * @throws Exception
     */
    private function number(int $length): string
    {
        $number = '';
        for ($i = 0; $i < $length; $i++) {
            $number .= (string) random_int(0, 9);
        }

        return $number;
    }

    /**
     * Stores the data in the cache.
     *
     * @param CacheItemInterface $otpAdapter The OTP adapter.
     * @param string $secret The secret.
     * @param int $retry The number of retries.
     * @param int $ttl The time to live in seconds.
     */
    private function storeData(CacheItemInterface $otpAdapter, string $secret, int $retry, int $ttl): void
    {
        if ($ttl < 1) {
            return;
        }
        $this->getCacheAdapter()->save(
            $otpAdapter->set([
                'secret' => $secret,
                'retry' => $retry,
                'expiresAt' => time() + $ttl,
            ])->expiresAfter($ttl),
        );
    }

    /**
     * Validates the requirement for the PHP function.
     *
     * @throws Exception The number of digits must be between 4 and 10.
     * @throws Exception The number of retries must be at least 0.
     * @throws Exception Validity duration is invalid.
     */
    private function validateRequirements(): void
    {
        match (true) {
            $this->digitCount < 4 || $this->digitCount > 10 => throw new Exception('The number of digits must be between 4 and 10.'),
            $this->retry < 0 => throw new Exception('The number of retries must be at least 0.'),
            $this->validUpto < 1 => throw new Exception('Validity duration is invalid.'),
            default => null,
        };
    }
}
