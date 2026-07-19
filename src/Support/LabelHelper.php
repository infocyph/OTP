<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class LabelHelper
{
    private const int MAX_LABEL_LENGTH = 255;

    public static function formatLabel(string $label, ?string $issuer = null): string
    {
        $label = trim($label);
        self::assertText($label, 'Label');

        if ($issuer === null || $issuer === '') {
            return $label;
        }

        $normalizedIssuer = self::normalizeIssuer($issuer);
        $prefix = $normalizedIssuer . ':';
        if (str_starts_with($label, $prefix)) {
            return $label;
        }

        $parts = explode(':', $label, 2);
        if (count($parts) === 2 && trim($parts[0]) === $normalizedIssuer) {
            return $normalizedIssuer . ':' . $parts[1];
        }

        return $prefix . $label;
    }

    public static function normalizeIssuer(string $issuer): string
    {
        $issuer = trim($issuer);
        self::assertText($issuer, 'Issuer');

        return preg_replace('/\s+/', ' ', $issuer) ?? $issuer;
    }

    /**
     * @param $label Provisioning label.
     * @param $issuer Optional issuer override.
     * @return array Parsed issuer/label parts.
     * @phpstan-return array{issuer:?string,label:string}
     */
    public static function parseLabel(string $label, ?string $issuer = null): array
    {
        if (preg_match('/%(?![A-Fa-f0-9]{2})/', $label) === 1) {
            throw new InvalidArgumentException('Provisioning label contains invalid percent encoding.');
        }

        $decoded = rawurldecode($label);
        self::assertText($decoded, 'Provisioning label');
        $queryIssuer = $issuer !== null && $issuer !== '' ? self::normalizeIssuer($issuer) : null;

        if (str_contains($decoded, ':')) {
            return self::parseIssuerLabel($decoded, $queryIssuer);
        }

        $decoded = trim($decoded);
        if ($decoded === '') {
            throw new InvalidArgumentException('Provisioning account label cannot be empty.');
        }

        return [
            'issuer' => $queryIssuer,
            'label' => $decoded,
        ];
    }

    private static function assertText(string $value, string $field): void
    {
        if (
            $value === ''
            || strlen($value) > self::MAX_LABEL_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
            || preg_match('//u', $value) !== 1
        ) {
            throw new InvalidArgumentException(sprintf('%s must contain between 1 and 255 valid UTF-8 bytes without control characters.', $field));
        }
    }

    /**
     * @param $decoded Decoded provisioning label.
     * @param $queryIssuer Normalized query-string issuer.
     * @return array Parsed issuer/label parts.
     * @phpstan-return array{issuer:?string,label:string}
     */
    private static function parseIssuerLabel(string $decoded, ?string $queryIssuer): array
    {
        [$labelIssuer, $account] = explode(':', $decoded, 2);
        $labelIssuer = trim($labelIssuer);
        $account = trim($account);
        if ($account === '') {
            throw new InvalidArgumentException('Provisioning account label cannot be empty.');
        }

        $labelIssuer = $labelIssuer !== '' ? self::normalizeIssuer($labelIssuer) : '';
        if ($labelIssuer !== '' && $queryIssuer !== null && $labelIssuer !== $queryIssuer) {
            throw new InvalidArgumentException('Provisioning label issuer must match the issuer query parameter.');
        }

        return [
            'issuer' => $queryIssuer ?? ($labelIssuer !== '' ? $labelIssuer : null),
            'label' => $account,
        ];
    }
}
