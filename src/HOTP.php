<?php

namespace Infocyph\OTP;

class HOTP
{
    use Common;


    /**
     * Initializes a new instance of the class.
     *
     * @param string $secret The secret key.
     * @param int $digitCount The number of digits in the generated code. Default is 6.
     */
    public function __construct(
        string $secret,
        int $digitCount = 6
    ) {
        $this->secret = $secret;
        $this->digitCount = $digitCount;
        $this->period = 1;
        $this->type = 'hotp';
    }

    /**
     * Sets the initial counter value.
     *
     * Required if Provisioning resources need to manipulate based on a specific counter.
     *
     * @param int $counter The new value for the counter.
     * @return static
     */
    public function setCounter(int $counter): static
    {
        $this->counter = $counter;
        return $this;
    }

    /**
     * Generates a one-time password (OTP) based on the given Counter.
     *
     * @param int $counter The input value used to generate the OTP.
     * @return string The generated OTP.
     */
    public function getOTP(int $counter): string
    {
        return $this->getPassword($counter);
    }

    /**
     * Verifies if the given OTP matches the OTP generated based on the given Counter.
     *
     * @param string $otp The OTP to be verified.
     * @param int $counter The input used to generate the OTP.
     * @return bool Returns true if the OTP matches the generated one, otherwise false.
     */
    public function verify(string $otp, int $counter): bool
    {
        return hash_equals($otp, $this->getOTP($counter));
    }
}
