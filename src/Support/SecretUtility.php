<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Exception;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;

final class SecretUtility
{
    /**
     * @throws Exception
     */
    public static function generate(int $bytes = 64): string
    {
        if ($bytes < 10) {
            throw new InvalidArgumentException('Secret byte length must be at least 10.');
        }

        return rtrim(Base32::encodeUpper(random_bytes($bytes)), '=');
    }

    public static function isValidBase32(string $secret): bool
    {
        try {
            self::normalizeBase32($secret);

            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public static function normalizeBase32(string $secret): string
    {
        $secret = strtoupper(str_replace([' ', "\t", "\r", "\n", '-'], '', trim($secret)));
        $secret = rtrim($secret, '=');
        if ($secret === '') {
            throw new InvalidArgumentException('Secret cannot be empty.');
        }
        if (!preg_match('/^[A-Z2-7]+$/', $secret)) {
            throw new InvalidArgumentException('Secret must be a valid Base32 string.');
        }

        return $secret;
    }
}
