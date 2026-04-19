<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;
use InvalidArgumentException;

final class ProvisioningUriParser
{
    public static function parse(string $uri): ParsedOtpAuthUri
    {
        $parts = parse_url($uri);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'otpauth') {
            throw new InvalidArgumentException('Invalid otpauth URI.');
        }

        $type = strtolower($parts['host'] ?? '');
        if (!in_array($type, ['hotp', 'totp', 'ocra'], true)) {
            throw new InvalidArgumentException('Unsupported otpauth type.');
        }

        parse_str($parts['query'] ?? '', $query);
        $secret = SecretUtility::normalizeBase32(self::stringQueryValue($query, 'secret'));
        $issuerValue = self::optionalStringQueryValue($query, 'issuer');
        $issuer = $issuerValue !== null ? LabelHelper::normalizeIssuer($issuerValue) : null;
        $labelParts = LabelHelper::parseLabel(ltrim((string) ($parts['path'] ?? ''), '/'), $issuer);
        $algorithmValue = self::optionalStringQueryValue($query, 'algorithm');
        $algorithm = $algorithmValue !== null ? AlgorithmValidator::normalize($algorithmValue) : 'sha1';
        $digits = isset($query['digits']) ? (int) $query['digits'] : 6;

        return new ParsedOtpAuthUri(
            $type,
            $secret,
            $labelParts['label'],
            $labelParts['issuer'],
            $algorithm,
            $digits,
            isset($query['period']) ? (int) $query['period'] : null,
            isset($query['counter']) ? (int) $query['counter'] : null,
            self::optionalStringQueryValue($query, 'ocraSuite'),
        );
    }

    /**
     * @param array<array-key, mixed> $query
     */
    private static function optionalStringQueryValue(array $query, string $key): ?string
    {
        if (!array_key_exists($key, $query)) {
            return null;
        }

        $value = $query[$key];
        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf('Invalid otpauth query parameter "%s".', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $query
     */
    private static function stringQueryValue(array $query, string $key): string
    {
        $value = self::optionalStringQueryValue($query, $key);
        if ($value === null) {
            throw new InvalidArgumentException(sprintf('Missing required otpauth query parameter "%s".', $key));
        }

        return $value;
    }
}
