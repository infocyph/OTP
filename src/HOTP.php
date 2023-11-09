<?php

namespace AbmmHasan\OTP;

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
        $this->steps = 1;
    }

    /**
     * Retrieves the QR image for a given name and title.
     *
     * @param string $name The name to generate the QR image for.
     * @param string|null $title The title to be displayed on the QR image. (optional)
     * @return string The QR image URL.
     */
    public function getQRImage(string $name, string $title = null): string
    {
        return $this->getImage('hotp', $name, $title);
    }

    /**
     * Generates a one-time password (OTP) based on the given Counter.
     *
     * @param int $counter The input value used to generate the OTP.
     * @return int The generated OTP.
     */
    public function getOTP(int $counter): int
    {
        return $this->getPassword($counter);
    }

    /**
     * Verifies if the given OTP matches the OTP generated based on the given Counter.
     *
     * @param int $otp The OTP to be verified.
     * @param int $counter The input used to generate the OTP.
     * @return bool Returns true if the OTP matches the generated OTP, otherwise false.
     */
    public function verify(int $otp, int $counter): bool
    {
        return $otp === $this->getOTP($counter);
    }
}
