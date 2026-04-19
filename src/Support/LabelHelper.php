<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class LabelHelper
{
    public static function formatLabel(string $label, ?string $issuer = null): string
    {
        $label = trim($label);
        if ($label === '') {
            throw new InvalidArgumentException('Label cannot be empty.');
        }

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
        if ($issuer === '') {
            throw new InvalidArgumentException('Issuer cannot be empty.');
        }

        return preg_replace('/\s+/', ' ', $issuer) ?? $issuer;
    }

    /**
     * @return array{issuer:?string,label:string}
     */
    public static function parseLabel(string $label, ?string $issuer = null): array
    {
        $decoded = rawurldecode($label);
        $queryIssuer = $issuer !== null && $issuer !== '' ? self::normalizeIssuer($issuer) : null;

        if (str_contains($decoded, ':')) {
            [$labelIssuer, $account] = explode(':', $decoded, 2);
            $labelIssuer = trim($labelIssuer);

            return [
                'issuer' => $queryIssuer ?? ($labelIssuer !== '' ? $labelIssuer : null),
                'label' => trim($account),
            ];
        }

        return [
            'issuer' => $queryIssuer,
            'label' => trim($decoded),
        ];
    }
}
