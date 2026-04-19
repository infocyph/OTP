<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class AlgorithmValidator
{
    public static function normalize(string $algorithm): string
    {
        $algorithm = strtolower(trim($algorithm));
        if (!in_array($algorithm, self::supported(), true)) {
            throw new InvalidArgumentException('Unsupported OTP algorithm.');
        }

        return $algorithm;
    }

    /**
     * @return array<string>
     */
    public static function supported(): array
    {
        return ['sha1', 'sha256', 'sha512'];
    }
}
