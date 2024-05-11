<?php

namespace Infocyph\OTP;

use Exception;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\CacheItem;

final class OTP
{
    private FilesystemAdapter $cacheAdapter;

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
        private string $hashAlgorithm = 'sha256'
    ) {
        $this->cacheAdapter = new FilesystemAdapter();
    }

    /**
     * Generates an OTP and saves it in the cache.
     *
     * @param string $signature The signature to generate the OTP for.
     * @return int The generated OTP.
     * @throws InvalidArgumentException|Exception
     */
    public function generate(string $signature): int
    {
        $this->validateRequirements();
        $otpAdapter = $this->cacheAdapter->getItem('ao-otp_' . base64_encode($signature));
        $otp = $this->number($this->digitCount);
        $this->storeData($otpAdapter, hash($this->hashAlgorithm, $otp), $this->retry, $this->validUpto);
        return $otp;
    }

    /**
     * Verifies the given signature and OTP.
     *
     * @param string $signature The signature to be verified.
     * @param int $otp The one-time password (OTP) to be verified.
     * @param bool $deleteIfFound Whether to delete the OTP from the cache if found (disregarding verification).
     * @return bool Returns true if the signature and OTP are verified successfully, false otherwise.
     * @throws InvalidArgumentException
     */
    public function verify(string $signature, int $otp, bool $deleteIfFound = true): bool
    {
        if ($otp < 0 || strlen($otp) !== $this->digitCount) {
            return false;
        }
        $signature = 'ao-otp_' . base64_encode($signature);
        $otpAdapter = $this->cacheAdapter->getItem($signature);
        if (!$otpAdapter->isHit()) {
            return false;
        }
        ['secret' => $secret, 'retry' => $retry, 'expiresAt' => $expiresAt] = $otpAdapter->get();
        $isVerified = hash_equals($secret, hash($this->hashAlgorithm, $otp));
        match (true) {
            $deleteIfFound || $isVerified || $retry < 1 => $this->cacheAdapter->deleteItem($signature),
            default => $this->storeData($otpAdapter, $secret, --$retry, $expiresAt - time())
        };
        return $isVerified;
    }

    /**
     * Deletes an OTP based on the given signature.
     *
     * @param string $signature The signature of the item to be deleted.
     * @return bool True if the item was successfully deleted, false otherwise.
     * @throws InvalidArgumentException
     */
    public function delete(string $signature): bool
    {
        return $this->cacheAdapter->deleteItem('ao-otp_' . base64_encode($signature));
    }

    /**
     * Flushes all the OTPs.
     *
     * @return bool
     */
    public function flush(): bool
    {
        return $this->cacheAdapter->clear();
    }

    /**
     * Stores the data in the cache.
     *
     * @param CacheItem $otpAdapter The OTP adapter.
     * @param string $secret The secret.
     * @param int $retry The number of retries.
     * @param int $ttl The time to live in seconds.
     * @return void
     */
    private function storeData(CacheItem $otpAdapter, string $secret, int $retry, int $ttl): void
    {
        if ($ttl < 1) {
            return;
        }
        $this->cacheAdapter->save(
            $otpAdapter->set([
                'secret' => $secret,
                'retry' => $retry,
                'expiresAt' => time() + $ttl
            ])->expiresAfter($ttl)
        );
    }

    /**
     * Validates the requirement for the PHP function.
     *
     * @throws Exception The number of digits must be between 2 and PHP_INT_SIZE.
     * @throws Exception The number of retries must be at least 0.
     * @throws Exception Validity duration is invalid.
     */
    private function validateRequirements(): void
    {
        match (true) {
            $this->digitCount < 2 || $this->digitCount > PHP_INT_SIZE
            => throw new Exception('The number of digits must be between 2 and ' . PHP_INT_SIZE . '.'),
            $this->retry < 0
            => throw new Exception('The number of retries must be atleast 0.'),
            $this->validUpto < 1
            => throw new Exception('Validity duration is invalid.'),
            default => null
        };
    }

    /**
     * Generate Secure random number of given length
     *
     * @param int $length
     * @return int
     * @throws Exception
     */
    private function number(int $length): int
    {
        return random_int(
            (int)('1' . str_repeat('0', $length - 1)),
            (int)str_repeat('9', $length)
        );
    }
}
