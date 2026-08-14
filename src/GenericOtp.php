<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\OTP\Contracts\OtpStoreInterface;
use InvalidArgumentException;

final readonly class GenericOtp
{
    private const int MAX_BINDING_LENGTH = 4096;

    private const int MAX_KEY_LENGTH = 1024;

    private const int MAX_TTL_SECONDS = 86400;

    public function __construct(
        private OtpStoreInterface $store,
        #[\SensitiveParameter]
        private string $key,
        private int $digits = 6,
        private int $ttlSeconds = 300,
        private int $maxAttempts = 3,
    ) {
        if ($digits < 6 || $digits > 10) {
            throw new InvalidArgumentException('Generic OTP digit count must be between 6 and 10.');
        }
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('Generic OTP validity must be between 1 and 86400 seconds.');
        }
        if ($maxAttempts < 1 || $maxAttempts > 10) {
            throw new InvalidArgumentException('Generic OTP max attempts must be between 1 and 10.');
        }
        if (strlen($key) < 16 || strlen($key) > self::MAX_KEY_LENGTH) {
            throw new InvalidArgumentException('Generic OTP HMAC keys must contain between 16 and 1024 bytes.');
        }
    }

    public function delete(string $binding): bool
    {
        self::assertBinding($binding);

        return $this->store->delete(self::storageBinding($binding));
    }

    public function generate(string $binding): string
    {
        self::assertBinding($binding);
        $now = time();
        if ($now > PHP_INT_MAX - $this->ttlSeconds) {
            throw new InvalidArgumentException('Generic OTP expiration exceeds the supported timestamp range.');
        }

        $otp = self::randomDigits($this->digits);
        $this->store->issue(
            self::storageBinding($binding),
            $this->digest($binding, $otp),
            $now + $this->ttlSeconds,
            $this->maxAttempts,
        );

        return $otp;
    }

    public function verify(string $binding, #[\SensitiveParameter] string $otp): bool
    {
        self::assertBinding($binding);
        if (strlen($otp) !== $this->digits || !ctype_digit($otp)) {
            return false;
        }

        return $this->store->verifyAndConsume(
            self::storageBinding($binding),
            $this->digest($binding, $otp),
            time(),
        );
    }

    private static function assertBinding(string $binding): void
    {
        if ($binding === '' || strlen($binding) > self::MAX_BINDING_LENGTH) {
            throw new InvalidArgumentException('Generic OTP bindings must contain between 1 and 4096 bytes.');
        }
    }

    private static function randomDigits(int $length): string
    {
        $number = '';
        while (strlen($number) < $length) {
            $bytes = random_bytes(max(1, $length - strlen($number)));
            $byteCount = strlen($bytes);
            for ($index = 0; $index < $byteCount; $index++) {
                $value = ord($bytes[$index]);
                if ($value < 250) {
                    $number .= chr(48 + ($value % 10));
                }
            }
        }

        return $number;
    }

    private static function storageBinding(string $binding): string
    {
        return hash('sha256', $binding);
    }

    private function digest(string $binding, string $otp): string
    {
        return hash_hmac('sha256', "generic-otp\0" . $binding . "\0" . $otp, $this->key);
    }
}
