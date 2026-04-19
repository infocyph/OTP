<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;

final class OtpMath
{
    public static function hotp(string $secret, int $counter, int $digits, string $algorithm): string
    {
        if ($counter < 0) {
            throw new InvalidArgumentException('Counter must be non-negative.');
        }
        if ($digits < 4 || $digits > 10) {
            throw new InvalidArgumentException('Digit count must be between 4 and 10.');
        }

        $algorithm = AlgorithmValidator::normalize($algorithm);
        $secret = SecretUtility::normalizeBase32($secret);
        $binaryCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        $hash = hash_hmac($algorithm, $binaryCounter, Base32::decodeUpper($secret), true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $unpacked = unpack('Nvalue', substr($hash, $offset, 4));
        if ($unpacked === false) {
            throw new InvalidArgumentException('Unable to unpack HOTP hash fragment.');
        }
        $value = $unpacked['value'];
        if (!is_int($value)) {
            throw new InvalidArgumentException('Invalid HOTP hash fragment value.');
        }

        return str_pad((string) (($value & 0x7FFFFFFF) % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }
}
