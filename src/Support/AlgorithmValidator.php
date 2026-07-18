<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class AlgorithmValidator
{
    public static function normalize(string $algorithm): string
    {
        $algorithm = strtolower(trim($algorithm));

        return match ($algorithm) {
            'sha1', 'sha256', 'sha512' => $algorithm,
            default => throw new InvalidArgumentException('Unsupported OTP algorithm.'),
        };
    }

    /**
     * @return array Supported OTP algorithm names.
     * @phpstan-return list<string>
     */
    public static function supported(): array
    {
        return ['sha1', 'sha256', 'sha512'];
    }
}
