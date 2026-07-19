<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class OcraSuiteValidator
{
    private const string PATTERN = '/^OCRA-1:HOTP-SHA(?:1|256|512)-(?:0|[4-9]|10):(?:C-)?Q[ANH](?:0[4-9]|[1-5]\d|6[0-4])(?:-P(?:SHA1|SHA256|SHA512))?(?:-S\d{3})?(?:-T(?:(?:[1-9]|[1-3]\d|4[0-8])H|(?:[1-9]|[1-5]\d)[SM]))?$/';

    public static function digitCount(string $suite): int
    {
        if (!self::isValid($suite)) {
            throw new InvalidArgumentException('Invalid OCRA suite.');
        }

        $cryptoFunction = explode(':', $suite, 3)[1];

        return (int) substr($cryptoFunction, strrpos($cryptoFunction, '-') + 1);
    }

    public static function isValid(string $suite): bool
    {
        return preg_match(self::PATTERN, $suite) === 1;
    }
}
