<?php

namespace Infocyph\OTP;

use Infocyph\OTP\Traits\Common;

final class TOTP
{
    use Common;

    /**
     * Initializes a new instance of the class.
     *
     * @param  string  $secret  The secret key.
     * @param  int  $digitCount  The number of digits in the generated code. Default is 6.
     * @param  int  $interval  The time interval in seconds. Default is 30.
     */
    public function __construct(
        string $secret,
        int $digitCount = 6,
        int $interval = 30
    ) {
        $this->secret = $secret;
        $this->digitCount = $digitCount;
        $this->period = $interval;
    }

    /**
     * Generates a one-time password (OTP) based on the given timestamp (or Current Timestamp).
     *
     * @param  int|null  $input  The input value used to generate the OTP. If null, the current timestamp is used.
     * @return string The generated OTP.
     */
    public function getOTP(?int $input = null): string
    {
        return $this->getPassword($input ?? time());
    }

    /**
     * Verifies the provided OTP against the generated OTP for the given timestamp (or Current Timestamp).
     *
     * @param  string  $otp  The OTP to be verified.
     * @param  int|null  $timestamp  The timestamp for which the OTP is to be generated. Defaults to Current Timestamp.
     * @param  bool  $leeway  Whether to allow a time leeway for OTP verification.
     * @return bool Returns true if the provided OTP matches the generated OTP, false otherwise.
     */
    public function verify(string $otp, ?int $timestamp = null, bool $leeway = false): bool
    {
        $isVerified = hash_equals($otp, $this->getOTP($timestamp));
        if (! $isVerified && $leeway) {
            return hash_equals($otp, $this->getOTP(($timestamp ?? time()) - $this->period));
        }

        return $isVerified;
    }
}
