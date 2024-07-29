<?php

namespace Infocyph\OTP\Traits;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Exception;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;

trait Common
{
    private string $secret;
    private int $period = 0;
    private int $counter = 0;
    private int $digitCount = 6;
    private ?string $issuer = null;
    private string $algorithm = 'sha1';
    private string $type = 'totp';
    private ?string $label = null;
    private ?string $ocraSuiteString = null;

    /**
     * Generates a secret string
     *
     * @return string The generated secret string.
     * @throws Exception
     */
    public static function generateSecret(): string
    {
        return rtrim(Base32::encodeUpper(random_bytes(64)), '=');
    }

    /**
     * Set the algorithm for the OTP generation.
     *
     * @param string $algorithm The algorithm to set.
     * @return static
     */
    public function setAlgorithm(string $algorithm): static
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Set the OCRA suite for the OTP generation.
     *
     * @param string $ocraSuiteString The OCRA suite to set.
     * @return static
     */
    public function setOcraSuite(string $ocraSuiteString): static
    {
        $this->ocraSuiteString = $ocraSuiteString;
        $this->type = 'ocra';
        return $this;
    }

    /**
     * Get the algorithm from the OCRA suite.
     *
     * @return string The algorithm.
     */
    private function getAlgorithmFromSuite(): string
    {
        preg_match('/HOTP-(SHA\d+)/', $this->ocraSuiteString, $matches);
        return $matches[1] ?? 'SHA1';
    }

    /**
     * Get the number of digits from the OCRA suite.
     *
     * @return int The number of digits.
     */
    private function getDigitsFromSuite(): int
    {
        preg_match('/-(\d{1,2}):/', $this->ocraSuiteString, $matches);
        return (int)($matches[1] ?? 6);
    }

    /**
     * Generates the provisioning URI for the given label, issuer, and optional parameters.
     *
     * @param string $label The label for the provisioning URI.
     * @param string $issuer The issuer for the provisioning URI.
     * @param array $include An array of optional parameters to include in the provisioning URI. Default is ['algorithm', 'digits', 'period', 'counter'].
     * @return string The provisioning URI as a string.
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period', 'counter']
    ): string {
        $include = array_flip($include);
        $query = [
            'secret' => $this->secret,
            'issuer' => $issuer,
        ];

        $query += match ($this->type) {
            'ocra' => [
                'ocraSuite' => $this->ocraSuiteString,
                'algorithm' => isset($include['algorithm']) ? strtoupper($this->getAlgorithmFromSuite()) : null,
                'digits' => isset($include['digits']) ? $this->getDigitsFromSuite() : null
            ],
            default => [
                'algorithm' => isset($include['algorithm']) ? $this->algorithm : null,
                'digits' => isset($include['digits']) ? $this->digitCount : null,
                'period' => $this->type === 'totp' && isset($include['period']) ? $this->period : null,
                'counter' => isset($include['counter']) ? $this->counter : null
            ]
        };

        $queryString = http_build_query(
            array_filter($query),
            encoding_type: PHP_QUERY_RFC3986
        );

        $label = rawurlencode(($issuer ? $issuer . ':' : '') . $label);

        return "otpauth://$this->type/$label?$queryString";
    }

    /**
     * Generates the provisioning QR code for the given label, issuer, and optional parameters.
     *
     * @param string $label The label for the provisioning QR code.
     * @param string $issuer The issuer for the provisioning QR code.
     * @param array $include An array of optional parameters to include in the provisioning QR code. Default is ['algorithm', 'digits', 'period', 'counter'].
     * @param int $imageSize The size of the QR code image.
     * @return string The provisioning QR code as SVG string.
     */
    public function getProvisioningUriQR(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period', 'counter'],
        int $imageSize = 200
    ): string {
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle($imageSize),
                new SvgImageBackEnd()
            )
        );
        return $writer->writeString($this->getProvisioningUri($label, $issuer, $include));
    }

    /**
     * Generates a one-time password (OTP) based on the given input.
     *
     * @param int $input The input value used to generate the OTP.
     * @return string The generated one-time password.
     */
    private function getPassword(int $input): string
    {
        $timeCode = (int)(($input * 1000) / ($this->period * 1000));
        $result = [];
        while ($timeCode !== 0) {
            $result[] = chr($timeCode & 0xFF);
            $timeCode >>= 8;
        }
        $intToByteString = str_pad(
            implode('', array_reverse($result)),
            8,
            "\000",
            STR_PAD_LEFT
        );
        $hash = hash_hmac($this->algorithm, $intToByteString, Base32::decodeUpper($this->secret), true);
        $unpacked = unpack('C*', $hash);
        $unpacked !== false || throw new InvalidArgumentException('Invalid data.');
        $hmac = array_values($unpacked);
        $offset = $hmac[count($hmac) - 1] & 0xf;
        $code = ($hmac[$offset] & 0x7F) << 24 |
            ($hmac[$offset + 1] & 0xFF) << 16 |
            ($hmac[$offset + 2] & 0xFF) << 8 |
            ($hmac[$offset + 3] & 0xFF);
        return str_pad(
            $code % 10 ** $this->digitCount,
            $this->digitCount,
            '0',
            STR_PAD_LEFT
        );
    }
}
