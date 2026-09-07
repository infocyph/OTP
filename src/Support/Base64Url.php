<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

/** @internal */
final class Base64Url
{
    public static function decode(string $value, string $name = 'Value'): string
    {
        if (
            $value === ''
            || strlen($value) % 4 === 1
            || preg_match('/\A[A-Za-z0-9_-]+\z/D', $value) !== 1
        ) {
            throw new InvalidArgumentException($name . ' must be valid URL-safe Base64 without padding.');
        }

        $base64 = strtr($value, '-_', '+/');
        $padding = (4 - (strlen($base64) % 4)) % 4;
        $decoded = base64_decode($base64 . str_repeat('=', $padding), true);
        if ($decoded === false || !hash_equals(self::encode($decoded), $value)) {
            throw new InvalidArgumentException($name . ' must be valid URL-safe Base64 without padding.');
        }

        return $decoded;
    }

    public static function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
