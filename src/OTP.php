<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Exception;
use InvalidArgumentException as NativeInvalidArgumentException;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use RuntimeException;

final readonly class OTP
{
    private const string CACHE_KEY_PREFIX = 'ao-otp_';

    private const int MAX_RETRIES = 100;

    private const int MAX_SIGNATURE_LENGTH = 4096;

    private const int MAX_VALIDITY_SECONDS = 86400;

    private int $digitCount;

    private string $hashAlgorithm;

    private ?string $hashKey;

    private int $retry;

    private int $validUpto;

    /**
     * Constructor for the class.
     *
     * @param int $digitCount The number of digits.
     * @param int $validUpto The number of seconds until the code expires.
     * @param int $retry The number of allowed retries.
     * @param string $hashAlgorithm Hashing algorithm used for stored OTPs.
     * @param CacheItemPoolInterface|null $cacheAdapter PSR-6 cache adapter.
     * @param string|null $hashKey Optional application HMAC key.
     */
    public function __construct(
        int $digitCount = 6,
        int $validUpto = 30,
        int $retry = 3,
        string $hashAlgorithm = 'sha256',
        private ?CacheItemPoolInterface $cacheAdapter = null,
        ?string $hashKey = null,
    ) {
        if ($digitCount < 4 || $digitCount > 10) {
            throw new NativeInvalidArgumentException('The number of digits must be between 4 and 10.');
        }
        if ($retry < 0 || $retry > self::MAX_RETRIES) {
            throw new NativeInvalidArgumentException('The number of retries must be between 0 and 100.');
        }
        if ($validUpto < 1 || $validUpto > self::MAX_VALIDITY_SECONDS) {
            throw new NativeInvalidArgumentException('Validity duration must be between 1 and 86400 seconds.');
        }

        $this->digitCount = $digitCount;
        $this->validUpto = $validUpto;
        $this->retry = $retry;
        $this->hashAlgorithm = match (strtolower(trim($hashAlgorithm))) {
            'sha256' => 'sha256',
            'sha512' => 'sha512',
            default => throw new NativeInvalidArgumentException('Generic OTP storage requires SHA-256 or SHA-512.'),
        };
        if ($hashKey !== null && strlen($hashKey) < 16) {
            throw new NativeInvalidArgumentException('Generic OTP HMAC keys must contain at least 16 bytes.');
        }
        $this->hashKey = $hashKey;
    }

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
        return $this->getCacheAdapter()->deleteItem($this->cacheKey($signature));
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
        $otpAdapter = $this->getCacheAdapter()->getItem($this->cacheKey($signature));
        $otp = $this->number($this->digitCount);
        $this->storeData($otpAdapter, $this->hash($otp), $this->retry, $this->validUpto);

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
        if (strlen($otp) !== $this->digitCount || !ctype_digit($otp)) {
            return false;
        }
        $signature = $this->cacheKey($signature);
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
            $cacheAdapter->deleteItem($signature);

            return false;
        }

        $secret = $payload['secret'];
        $retry = $payload['retry'];
        $expiresAt = $payload['expiresAt'];
        $now = time();
        if ($expiresAt <= $now) {
            $cacheAdapter->deleteItem($signature);

            return false;
        }

        $isVerified = hash_equals($secret, $this->hash($otp));
        match (true) {
            $deleteIfFound || $isVerified || $retry < 1 => $cacheAdapter->deleteItem($signature),
            default => $this->storeData($otpAdapter, $secret, $retry - 1, $expiresAt - $now),
        };

        return $isVerified;
    }

    private function cacheKey(string $signature): string
    {
        if ($signature === '' || strlen($signature) > self::MAX_SIGNATURE_LENGTH) {
            throw new NativeInvalidArgumentException('Generic OTP signatures must contain between 1 and 4096 bytes.');
        }

        return self::CACHE_KEY_PREFIX . hash('sha256', $signature);
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

    private function hash(string $otp): string
    {
        if ($this->hashKey === null) {
            return hash($this->hashAlgorithm, $otp);
        }

        return hash_hmac($this->hashAlgorithm, $otp, $this->hashKey);
    }

    /**
     * Generate Secure random number of given length
     *
     * @param $length Number of digits to generate.
     *
     * @throws Exception
     */
    private function number(int $length): string
    {
        $number = '';
        while (strlen($number) < $length) {
            $bytes = random_bytes(max(1, $length - strlen($number)));
            $byteCount = strlen($bytes);
            for ($index = 0; $index < $byteCount; $index++) {
                $value = ord($bytes[$index]);
                if ($value >= 250) {
                    continue;
                }

                $number .= chr(48 + ($value % 10));
            }
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
     *
     * @throws Exception
     */
    private function storeData(CacheItemInterface $otpAdapter, string $secret, int $retry, int $ttl): void
    {
        if ($ttl < 1) {
            return;
        }
        $saved = $this->getCacheAdapter()->save(
            $otpAdapter->set([
                'secret' => $secret,
                'retry' => $retry,
                'expiresAt' => time() + $ttl,
            ])->expiresAfter($ttl),
        );
        if (!$saved) {
            throw new RuntimeException('Unable to persist generic OTP state.');
        }
    }
}
