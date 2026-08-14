<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Exception;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;
use Throwable;

final class SecretUtility
{
    public static function decodeBase32(#[\SensitiveParameter] string $secret): string
    {
        $normalized = self::normalizeBase32($secret);

        try {
            $decoded = Base32::decodeUpper($normalized);
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('Secret must be a valid Base32 string.', previous: $exception);
        }

        if (rtrim(Base32::encodeUpper($decoded), '=') !== $normalized) {
            throw new InvalidArgumentException('Secret must use canonical Base32 encoding.');
        }

        return $decoded;
    }

    /**
     * @param $bytes Secret byte length.
     * @throws Exception
     */
    public static function generate(int $bytes = 20): string
    {
        if ($bytes < 16 || $bytes > 1024) {
            throw new InvalidArgumentException('Secret byte length must be between 16 and 1024.');
        }

        return rtrim(Base32::encodeUpper(random_bytes($bytes)), '=');
    }

    public static function isValidBase32(#[\SensitiveParameter] string $secret): bool
    {
        try {
            self::decodeBase32($secret);

            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public static function normalizeBase32(#[\SensitiveParameter] string $secret): string
    {
        $secret = strtoupper(str_replace([' ', "\t", "\r", "\n", '-'], '', trim($secret)));
        $secret = rtrim($secret, '=');
        if ($secret === '') {
            throw new InvalidArgumentException('Secret cannot be empty.');
        }
        if (!preg_match('/^[A-Z2-7]+$/', $secret)) {
            throw new InvalidArgumentException('Secret must be a valid Base32 string.');
        }
        if (in_array(strlen($secret) % 8, [1, 3, 6], true)) {
            throw new InvalidArgumentException('Secret must be a valid Base32 string.');
        }

        return $secret;
    }

    public static function requireStrongBase32(#[\SensitiveParameter] string $secret): string
    {
        $decoded = self::decodeBase32($secret);
        if (strlen($decoded) < 16) {
            throw new InvalidArgumentException('OTP factor secrets must contain at least 16 decoded bytes.');
        }

        return $decoded;
    }
}
