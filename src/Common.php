<?php

namespace AbmmHasan\OTP;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Exception;
use ParagonIE\ConstantTime\Base32;

trait Common
{

    /**
     * Generates a secret string
     *
     * @return string The generated secret string.
     * @throws Exception
     */
    public static function generateSecret(): string
    {
        $string = bin2hex(random_bytes(5));
        $string = Base32::encodeUpper($string);
        return trim(strtoupper($string), '=');
    }

    /**
     * Initializes a new instance of the class.
     *
     * @param string $secret The secret key.
     * @param int $digitCount The number of digits in the generated code. Default is 6.
     * @param int $interval The time interval in seconds. Default is 30.
     */
    public function __construct(
        private string $secret,
        private int $digitCount = 6,
        private int $interval = 30,
    ) {
    }

    /**
     * Retrieves the image Resource for the given OTP type, name, and title.
     *
     * @param string $otpType The type of OTP.
     * @param string $name The name for the OTP.
     * @param string|null $title (Optional) The title for the OTP.
     * @return string The SVG image resource.
     */
    private function getImage(string $otpType, string $name, ?string $title): string
    {
        $url = "otpauth://$otpType/$name?secret=$this->secret";
        if (!empty($title)) {
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
     * Generates a one-time password (OTP) based on the given input.
     *
     * @param int $input The input value used to generate the OTP.
     * @return int The generated one-time password.
     */
    private function getPassword(int $input): int
    {
        $timeCode = ($input * 1000) / ($this->interval * 1000);
        $result = $hmac = [];
        while ($timeCode != 0) {
            $result[] = chr($timeCode & 0xFF);
            $timeCode >>= 8;
        }
        $intToByteString = str_pad(implode('', array_reverse($result)), 8, "\000", STR_PAD_LEFT);
        $hash = hash_hmac('sha1', $intToByteString, Base32::decodeUpper($this->secret));
        foreach (str_split($hash, 2) as $hex) {
            $hmac[] = hexdec($hex);
        }
        $offset = $hmac[19] & 0xf;
        $code = ($hmac[$offset + 0] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return $code % pow(10, $this->digitCount);
    }
}
