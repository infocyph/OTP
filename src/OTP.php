<?php

namespace AbmmHasan\OTP;

use Exception;
use Psr\Cache\InvalidArgumentException;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class OTP
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
        private int $validUpto = 30
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
        $otpAdapter = $this->cacheAdapter->getItem('ao-otp:' . base64_encode($signature));
        $otpAdapter->set($this->number($this->digitCount))->expiresAfter($this->validUpto);
        $this->cacheAdapter->save($otpAdapter);
        return $otpAdapter->get();
    }

    /**
     * Verifies the given signature and OTP.
     *
     * @param string $signature The signature to be verified.
     * @param int $otp The one-time password (OTP) to be verified.
     * @return bool Returns true if the signature and OTP are verified successfully, false otherwise.
     * @throws InvalidArgumentException
     */
    public function verify(string $signature, int $otp): bool
    {
        if ($otp < 0 || strlen($otp) !== $this->digitCount) {
            return false;
        }
        $signature = 'ao-otp:' . base64_encode($signature);
        $otpAdapter = $this->cacheAdapter->getItem($signature);
        if ($otpAdapter->isHit()) {
            $isVerified = $otpAdapter->get() === $otp;
            $this->cacheAdapter->deleteItem($signature);
            return $isVerified;
        }
        return false;
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
            intval('1' . str_repeat('0', $length - 1)),
            intval(str_repeat('9', $length))
        );
    }
}
