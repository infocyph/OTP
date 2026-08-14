<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\ValueObjects\OcraSuite;
use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;
use InvalidArgumentException;

final class ProvisioningUriParser
{
    private const int MAX_QUERY_PARAMETERS = 32;

    private const int MAX_URI_LENGTH = 4096;

    public static function parse(#[\SensitiveParameter] string $uri): ParsedOtpAuthUri
    {
        if ($uri === '' || strlen($uri) > self::MAX_URI_LENGTH) {
            throw new InvalidArgumentException('Invalid otpauth URI length.');
        }

        $parts = self::parseUriParts($uri);

        $type = strtolower($parts['host']);
        if (!in_array($type, ['hotp', 'totp', 'ocra'], true)) {
            throw new InvalidArgumentException('Unsupported otpauth type.');
        }

        $query = self::parseQuery($parts['query']);
        $secret = SecretUtility::normalizeBase32(self::stringQueryValue($query, 'secret'));
        SecretUtility::decodeBase32($secret);
        $issuerValue = self::optionalStringQueryValue($query, 'issuer');
        $issuer = $issuerValue !== null ? LabelHelper::normalizeIssuer($issuerValue) : null;
        $labelParts = LabelHelper::parseLabel(ltrim($parts['path'], '/'), $issuer);
        $algorithmValue = self::optionalStringQueryValue($query, 'algorithm');
        $algorithm = $algorithmValue !== null ? AlgorithmValidator::normalize($algorithmValue) : 'sha1';
        $digitsValue = self::optionalNonNegativeIntQueryValue($query, 'digits');
        $digits = $digitsValue ?? 6;
        if (($type === 'hotp' || $type === 'totp') && ($digits < 6 || $digits > 9)) {
            throw new InvalidArgumentException('HOTP and TOTP digit counts must be between 6 and 9.');
        }

        $period = self::optionalPositiveIntQueryValue($query, 'period');
        $counter = self::optionalNonNegativeIntQueryValue($query, 'counter');
        $ocraSuite = self::optionalStringQueryValue($query, 'ocraSuite');
        [$algorithm, $digits] = self::assertTypeParameters(
            $type,
            $algorithm,
            $algorithmValue !== null,
            $digits,
            $digitsValue !== null,
            $period,
            $counter,
            $ocraSuite,
        );
        $period = $type === 'totp' ? ($period ?? 30) : null;
        $additionalParameters = array_diff_key(
            $query,
            array_fill_keys(['secret', 'issuer', 'algorithm', 'digits', 'period', 'counter', 'ocraSuite'], true),
        );

        return new ParsedOtpAuthUri(
            $type,
            $secret,
            $labelParts['label'],
            $labelParts['issuer'],
            $algorithm,
            $digits,
            $period,
            $counter,
            $ocraSuite,
            $additionalParameters,
        );
    }

    private static function assertHotpParameters(
        int $digits,
        ?int $period,
        ?int $counter,
        ?string $ocraSuite,
    ): int {
        if ($counter === null) {
            throw new InvalidArgumentException('HOTP provisioning URIs require a counter.');
        }
        if ($period !== null) {
            throw new InvalidArgumentException('Only TOTP provisioning URIs may contain a period.');
        }
        if ($ocraSuite !== null) {
            throw new InvalidArgumentException('Only OCRA provisioning URIs may contain an OCRA suite.');
        }

        return $digits;
    }

    /**
     * @param string $algorithm Effective normalized algorithm.
     * @param bool $algorithmProvided Whether the URI explicitly supplied the algorithm.
     * @param int $digits Effective output width.
     * @param bool $digitsProvided Whether the URI explicitly supplied the width.
     * @param ?int $period Parsed period, which OCRA forbids.
     * @param ?int $counter Parsed counter, which OCRA forbids.
     * @param ?string $ocraSuite Required OCRA suite.
     * @return array{string,int}
     */
    private static function assertOcraParameters(
        string $algorithm,
        bool $algorithmProvided,
        int $digits,
        bool $digitsProvided,
        ?int $period,
        ?int $counter,
        ?string $ocraSuite,
    ): array {
        if ($counter !== null) {
            throw new InvalidArgumentException('Only HOTP provisioning URIs may contain a counter.');
        }
        if ($period !== null) {
            throw new InvalidArgumentException('Only TOTP provisioning URIs may contain a period.');
        }
        if ($ocraSuite === null || $ocraSuite === '') {
            throw new InvalidArgumentException('OCRA provisioning URIs require an OCRA suite.');
        }

        $suite = OcraSuite::parse($ocraSuite);
        if ($digitsProvided && $digits !== $suite->digits) {
            throw new InvalidArgumentException('OCRA digit count must match the provisioning suite.');
        }
        if ($algorithmProvided && $algorithm !== $suite->algorithm) {
            throw new InvalidArgumentException('OCRA algorithm must match the provisioning suite.');
        }

        return [$suite->algorithm, $suite->digits];
    }

    private static function assertTotpParameters(int $digits, ?int $counter, ?string $ocraSuite): int
    {
        if ($counter !== null) {
            throw new InvalidArgumentException('Only HOTP provisioning URIs may contain a counter.');
        }
        if ($ocraSuite !== null) {
            throw new InvalidArgumentException('Only OCRA provisioning URIs may contain an OCRA suite.');
        }

        return $digits;
    }

    /**
     * @param string $type Parsed otpauth factor type.
     * @param string $algorithm Effective normalized algorithm.
     * @param bool $algorithmProvided Whether the URI explicitly supplied the algorithm.
     * @param int $digits Effective output width.
     * @param bool $digitsProvided Whether the URI explicitly supplied the width.
     * @param ?int $period Parsed TOTP period.
     * @param ?int $counter Parsed HOTP counter.
     * @param ?string $ocraSuite Parsed OCRA suite.
     * @return array{string,int}
     */
    private static function assertTypeParameters(
        string $type,
        string $algorithm,
        bool $algorithmProvided,
        int $digits,
        bool $digitsProvided,
        ?int $period,
        ?int $counter,
        ?string $ocraSuite,
    ): array {
        return match ($type) {
            'hotp' => [$algorithm, self::assertHotpParameters($digits, $period, $counter, $ocraSuite)],
            'totp' => [$algorithm, self::assertTotpParameters($digits, $counter, $ocraSuite)],
            'ocra' => self::assertOcraParameters(
                $algorithm,
                $algorithmProvided,
                $digits,
                $digitsProvided,
                $period,
                $counter,
                $ocraSuite,
            ),
            default => throw new InvalidArgumentException('Unsupported otpauth type.'),
        };
    }

    /**
     * @param $query Parsed URI query values.
     * @param $key Query parameter name.
     * @phpstan-param array<string, string> $query
     */
    private static function optionalNonNegativeIntQueryValue(array $query, string $key): ?int
    {
        $value = self::optionalStringQueryValue($query, $key);
        if ($value === null) {
            return null;
        }
        if (!ctype_digit($value)) {
            throw new InvalidArgumentException(sprintf('Invalid non-negative integer otpauth query parameter "%s".', $key));
        }
        $canonical = ltrim($value, '0');
        $canonical = $canonical === '' ? '0' : $canonical;
        if ((string) (int) $canonical !== $canonical) {
            throw new InvalidArgumentException(sprintf('Otpauth query parameter "%s" exceeds the supported integer range.', $key));
        }

        return (int) $value;
    }

    /**
     * @param $query Parsed URI query values.
     * @param $key Query parameter name.
     * @phpstan-param array<string, string> $query
     */
    private static function optionalPositiveIntQueryValue(array $query, string $key): ?int
    {
        $value = self::optionalNonNegativeIntQueryValue($query, $key);
        if ($value !== null && ($value < 1 || $value > 86400)) {
            throw new InvalidArgumentException(sprintf('Otpauth query parameter "%s" must be between 1 and 86400.', $key));
        }

        return $value;
    }

    /**
     * @param $query Parsed URI query values.
     * @param $key Query parameter name.
     * @phpstan-param array<string, string> $query
     */
    private static function optionalStringQueryValue(array $query, string $key): ?string
    {
        if (!isset($query[$key])) {
            return null;
        }

        return $query[$key];
    }

    /**
     * @param $queryString Encoded URI query.
     * @return array Parsed query values.
     * @phpstan-return array<string, string>
     */
    private static function parseQuery(string $queryString): array
    {
        if ($queryString === '') {
            return [];
        }

        $parameters = explode('&', $queryString);
        if (count($parameters) > self::MAX_QUERY_PARAMETERS) {
            throw new InvalidArgumentException('Too many otpauth query parameters.');
        }

        $query = [];
        foreach ($parameters as $parameter) {
            if ($parameter === '') {
                throw new InvalidArgumentException('Invalid empty otpauth query parameter.');
            }

            [$encodedKey, $encodedValue] = array_pad(explode('=', $parameter, 2), 2, '');
            if (
                $encodedKey === ''
                || preg_match('/%(?![A-Fa-f0-9]{2})/', $encodedKey . $encodedValue) === 1
            ) {
                throw new InvalidArgumentException('Invalid otpauth query encoding.');
            }

            $key = rawurldecode($encodedKey);
            if (trim($key) === '' || preg_match('/[\x00-\x1F\x7F]/', $key) === 1) {
                throw new InvalidArgumentException('Invalid otpauth query parameter name.');
            }
            if (isset($query[$key])) {
                throw new InvalidArgumentException(sprintf('Duplicate otpauth query parameter "%s".', $key));
            }

            $canonicalReserved = [
                'secret' => 'secret',
                'issuer' => 'issuer',
                'algorithm' => 'algorithm',
                'digits' => 'digits',
                'period' => 'period',
                'counter' => 'counter',
                'ocrasuite' => 'ocraSuite',
            ];
            $lowerKey = strtolower($key);
            if (isset($canonicalReserved[$lowerKey]) && $key !== $canonicalReserved[$lowerKey]) {
                throw new InvalidArgumentException(sprintf('Reserved otpauth query parameter "%s" has invalid casing.', $key));
            }

            $query[$key] = rawurldecode($encodedValue);
        }

        return $query;
    }

    /**
     * @param $uri Provisioning URI.
     * @return array Parsed URI components.
     * @phpstan-return array{host:string,path:string,query:string}
     */
    private static function parseUriParts(string $uri): array
    {
        $parts = parse_url($uri);
        $scheme = is_array($parts) ? ($parts['scheme'] ?? null) : null;
        $host = is_array($parts) ? ($parts['host'] ?? null) : null;
        if (
            !is_array($parts)
            || !is_string($scheme)
            || strtolower($scheme) !== 'otpauth'
            || !is_string($host)
            || $host === ''
        ) {
            throw new InvalidArgumentException('Invalid otpauth URI.');
        }
        if (
            isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['port'])
            || isset($parts['fragment'])
        ) {
            throw new InvalidArgumentException('Invalid otpauth URI authority or fragment.');
        }

        $path = $parts['path'] ?? '';
        $query = $parts['query'] ?? '';

        return ['host' => $host, 'path' => $path, 'query' => $query];
    }

    /**
     * @param $query Parsed URI query values.
     * @param $key Query parameter name.
     * @phpstan-param array<string, string> $query
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
