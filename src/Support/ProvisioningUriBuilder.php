<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\OcraSuite;
use InvalidArgumentException;

final class ProvisioningUriBuilder
{
    /**
     * @param $type OTP type (`totp`, `hotp`, or `ocra`).
     * @param $secret Normalized Base32 secret.
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $algorithm HMAC algorithm name.
     * @param $digits OTP digit length.
     * @param $period TOTP period in seconds.
     * @param $counter HOTP counter value.
     * @param $ocraSuite OCRA suite string.
     * @phpstan-param array<string, bool> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public static function build(
        string $type,
        #[\SensitiveParameter]
        string $secret,
        string $label,
        string $issuer,
        array $include,
        array $additionalParameters = [],
        string $algorithm = 'sha1',
        int $digits = 6,
        ?int $period = null,
        ?int $counter = null,
        ?string $ocraSuite = null,
    ): string {
        self::assertType($type);
        self::assertAdditionalParameters($additionalParameters);
        $algorithm = AlgorithmValidator::normalize($algorithm);
        self::assertDigits($type, $digits);
        $period = self::normalizePeriod($type, $period);
        self::assertCounter($type, $counter);
        self::assertOcraSuite($type, $ocraSuite, $algorithm, $digits);
        $secret = SecretUtility::normalizeBase32($secret);
        SecretUtility::decodeBase32($secret);

        $query = [
            'secret' => $secret,
            'issuer' => LabelHelper::normalizeIssuer($issuer),
            'algorithm' => $include['algorithm'] ?? false ? strtoupper($algorithm) : null,
            'digits' => $include['digits'] ?? false ? $digits : null,
            'period' => $type === 'totp' && ($include['period'] ?? false) ? $period : null,
            'counter' => $type === 'hotp' ? $counter : null,
            'ocraSuite' => $type === 'ocra' ? $ocraSuite : null,
        ] + $additionalParameters;

        $label = rawurlencode(LabelHelper::formatLabel($label, $issuer));

        $uri = sprintf(
            'otpauth://%s/%s?%s',
            $type,
            $label,
            http_build_query(array_filter($query, static fn($value) => $value !== null), '', '&', PHP_QUERY_RFC3986),
        );
        if (strlen($uri) > 4096) {
            throw new InvalidArgumentException('Provisioning URI cannot exceed 4096 bytes.');
        }

        return $uri;
    }

    /**
     * @param $type OTP type (`totp`, `hotp`, or `ocra`).
     * @param $secret Normalized Base32 secret.
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $algorithm HMAC algorithm name.
     * @param $digits OTP digit length.
     * @param $period TOTP period in seconds.
     * @param $counter HOTP counter value.
     * @param $ocraSuite OCRA suite string.
     * @param $qrSvg Optional rendered QR SVG.
     * @phpstan-param array<string, bool> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public static function enrollmentPayload(
        string $type,
        #[\SensitiveParameter]
        string $secret,
        string $label,
        string $issuer,
        array $include,
        array $additionalParameters = [],
        string $algorithm = 'sha1',
        int $digits = 6,
        ?int $period = null,
        ?int $counter = null,
        ?string $ocraSuite = null,
        ?string $qrSvg = null,
    ): EnrollmentPayload {
        $secret = SecretUtility::normalizeBase32($secret);
        SecretUtility::decodeBase32($secret);
        $label = LabelHelper::normalizeAccountLabel($label);
        $issuer = LabelHelper::normalizeIssuer($issuer);
        $uri = self::build(
            $type,
            $secret,
            $label,
            $issuer,
            $include,
            $additionalParameters,
            $algorithm,
            $digits,
            $period,
            $counter,
            $ocraSuite,
        );

        return new EnrollmentPayload($secret, $uri, $issuer, $label, $qrSvg);
    }

    /**
     * @param $additionalParameters Additional query parameters.
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    private static function assertAdditionalParameters(array $additionalParameters): void
    {
        if (count($additionalParameters) > 24) {
            throw new InvalidArgumentException('Provisioning URIs may contain at most 24 additional parameters.');
        }

        $reservedParameters = array_fill_keys(
            ['secret', 'issuer', 'algorithm', 'digits', 'period', 'counter', 'ocrasuite'],
            true,
        );
        foreach ($additionalParameters as $key => $value) {
            if (
                trim($key) === ''
                || strlen($key) > 64
                || preg_match('/[\x00-\x1F\x7F]/', $key) === 1
            ) {
                throw new InvalidArgumentException('Provisioning query parameter names must contain between 1 and 64 printable bytes.');
            }
            if (isset($reservedParameters[strtolower($key)])) {
                throw new InvalidArgumentException(sprintf('Provisioning query parameter "%s" is reserved.', $key));
            }
            if (is_string($value) && strlen($value) > 1024) {
                throw new InvalidArgumentException('Provisioning query parameter values cannot exceed 1024 bytes.');
            }
        }
    }

    private static function assertCounter(string $type, ?int $counter): void
    {
        if ($type === 'hotp' && ($counter === null || $counter < 0)) {
            throw new InvalidArgumentException('HOTP counter must be non-negative.');
        }
        if ($type !== 'hotp' && $counter !== null) {
            throw new InvalidArgumentException('Only HOTP provisioning may contain a counter.');
        }
    }

    private static function assertDigits(string $type, int $digits): void
    {
        if (($type === 'hotp' || $type === 'totp') && ($digits < 6 || $digits > 9)) {
            throw new InvalidArgumentException('HOTP and TOTP digit counts must be between 6 and 9.');
        }
        if ($type === 'ocra' && $digits !== 0 && ($digits < 4 || $digits > 9)) {
            throw new InvalidArgumentException('OCRA digit count must be zero or between 4 and 9.');
        }
    }

    private static function assertOcraSuite(
        string $type,
        ?string $ocraSuite,
        string $algorithm,
        int $digits,
    ): void {
        if ($type === 'ocra' && ($ocraSuite === null || $ocraSuite === '')) {
            throw new InvalidArgumentException('OCRA provisioning requires an OCRA suite.');
        }
        if ($type === 'ocra') {
            $suite = OcraSuite::parse($ocraSuite);
            if ($suite->algorithm !== $algorithm || $suite->digits !== $digits) {
                throw new InvalidArgumentException('OCRA provisioning algorithm and digits must match the suite.');
            }
        }
        if ($type !== 'ocra' && $ocraSuite !== null) {
            throw new InvalidArgumentException('Only OCRA provisioning may contain an OCRA suite.');
        }
    }

    private static function assertType(string $type): void
    {
        if (!in_array($type, ['hotp', 'totp', 'ocra'], true)) {
            throw new InvalidArgumentException('Unsupported OTP provisioning type.');
        }
    }

    private static function normalizePeriod(string $type, ?int $period): ?int
    {
        if ($type !== 'totp') {
            if ($period !== null) {
                throw new InvalidArgumentException('Only TOTP provisioning may contain a period.');
            }

            return null;
        }

        $period ??= 30;
        if ($period < 1 || $period > 86400) {
            throw new InvalidArgumentException('TOTP period must be between 1 and 86400 seconds.');
        }

        return $period;
    }
}
