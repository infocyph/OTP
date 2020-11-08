<?php


namespace AbmmHasan\OTP;


use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use ParagonIE\ConstantTime\Base32;

class OTP
{
    private $secret;

    /**
     * Generate Secret
     *
     * @return string 16 digit secret
     * @throws \Exception
     */
    public function createSecret()
    {
        $string = strtoupper(bin2hex(random_bytes(5)));
        $string = Base32::encodeUpper($string);
        return trim(mb_strtoupper($string), '=');
    }

    /**
     * Generate QR Code for secret
     *
     * @param string $otp_type Otp type: totp or hotp
     * @param string $name
     * @param null|string $title
     * @return string
     */
    public function getQRSnap(string $otp_type, string $name, string $title = null)
    {
        if (!in_array($otp_type, ['totp', 'hotp'])) {
            throw new \InvalidArgumentException('Only totp or hotp type allowed');
        }
        $url = "otpauth://{$otp_type}/{$name}?secret={$this->secret}";
        if (isset($title)) {
            $url .= '&issuer=' . $title;
        }
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle(200),
                new SvgImageBackEnd()
            )
        );
        return $writer->writeString($url);
    }

    /**
     * Set secret for further process
     *
     * @param string $secret
     * @return $this
     */
    public function setSecret(string $secret)
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * Get TOTP code based on input or for current time
     *
     * @param int|null $input
     * @return int
     */
    public function getTOTP(int $input = null)
    {
        return $this->getOTP($input);
    }

    /**
     * Get HOTP code based on input counter
     *
     * @param int $counter
     * @return int
     */
    public function getHOTP(int $counter)
    {
        return $this->getOTP($counter, 6, 1);
    }

    /**
     * Verify OTP
     *
     * @param int $otp
     * @param int|null $input
     * @param string|null $type
     * @return bool
     */
    public function verify(int $otp, int $input = null, string $type = null)
    {
        switch (strtolower($type)) {
            case 'totp':
                return $otp == $this->getTOTP($input ?? time());
            case 'hotp':
                return $otp == $this->getHOTP($input);
            default:
                if (is_null($input)) {
                    return $otp == $this->getTOTP();
                }
                return $otp == $this->getHOTP($input);
        }
    }

    /**
     * Get OTP for current time or specified input
     *
     * @param int|null $input
     * @param int $digits
     * @param int $interval
     * @return int
     */
    private function getOTP(int $input = null, int $digits = 6, int $interval = 30)
    {
        $input = $input ?? time();
        $timeCode = ($input * 1000) / ($interval * 1000);
        $result = $hmac = [];
        while ($timeCode != 0) {
            $result[] = chr($timeCode & 0xFF);
            $timeCode >>= 8;
        }
        $intToByteString = str_pad(implode('',array_reverse($result)), 8, "\000", STR_PAD_LEFT);
        $hash = hash_hmac('sha1', $intToByteString, Base32::decodeUpper($this->secret));
        foreach (str_split($hash, 2) as $hex) {
            $hmac[] = hexdec($hex);
        }
        $offset = $hmac[19] & 0xf;
        $code = ($hmac[$offset + 0] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return $code % pow(10, $digits);
    }
}