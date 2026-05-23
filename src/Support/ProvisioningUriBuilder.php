<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\ValueObjects\EnrollmentPayload;

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
        $query = [
            'secret' => SecretUtility::normalizeBase32($secret),
            'issuer' => LabelHelper::normalizeIssuer($issuer),
            'algorithm' => $include['algorithm'] ?? false ? strtoupper($algorithm) : null,
            'digits' => $include['digits'] ?? false ? $digits : null,
            'period' => $type === 'totp' && ($include['period'] ?? false) ? $period : null,
            'counter' => $type === 'hotp' && ($include['counter'] ?? false) ? $counter : null,
            'ocraSuite' => $type === 'ocra' ? $ocraSuite : null,
        ] + $additionalParameters;

        $label = rawurlencode(LabelHelper::formatLabel($label, $issuer));

        return sprintf(
            'otpauth://%s/%s?%s',
            $type,
            $label,
            http_build_query(array_filter($query, static fn($value) => $value !== null), '', '&', PHP_QUERY_RFC3986),
        );
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

        return new EnrollmentPayload($secret, $uri, $uri, $issuer, $label, $qrSvg);
    }
}
