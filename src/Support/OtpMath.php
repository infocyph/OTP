<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class OtpMath
{
    private const array MODULUS = [
        6 => 1_000_000,
        7 => 10_000_000,
        8 => 100_000_000,
        9 => 1_000_000_000,
    ];

    /**
     * @param string $secret Canonical Base32 factor secret.
     * @param int $counter Non-negative moving factor.
     * @param int $digits Output width from six through nine.
     * @param string $algorithm Supported HMAC algorithm name.
     * @internal
     */
    public static function hotp(#[\SensitiveParameter] string $secret, int $counter, int $digits, string $algorithm): string
    {
        return self::hotpFromBinary(
            SecretUtility::decodeBase32($secret),
            $counter,
            $digits,
            AlgorithmValidator::normalize($algorithm),
        );
    }

    /**
     * The algorithm must already be normalized.
     *
     * @param string $binarySecret Decoded factor secret.
     * @param int $counter Non-negative moving factor.
     * @param int $digits Output width from six through nine.
     * @param string $algorithm Prevalidated HMAC algorithm name.
     * @internal
     */
    public static function hotpFromBinary(#[\SensitiveParameter] string $binarySecret, int $counter, int $digits, string $algorithm): string
    {
        if ($binarySecret === '') {
            throw new InvalidArgumentException('Binary OTP secret cannot be empty.');
        }
        if ($counter < 0) {
            throw new InvalidArgumentException('Counter must be non-negative.');
        }
        if (!isset(self::MODULUS[$digits])) {
            throw new InvalidArgumentException('Digit count must be between 6 and 9.');
        }
        $binaryCounter = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        $hash = hash_hmac($algorithm, $binaryCounter, $binarySecret, true);
        $offset = ord($hash[-1]) & 0x0F;
        $unpacked = unpack('Nvalue', substr($hash, $offset, 4));
        if ($unpacked === false) {
            throw new InvalidArgumentException('Unable to unpack HOTP hash fragment.');
        }
        $value = $unpacked['value'];
        if (!is_int($value)) {
            throw new InvalidArgumentException('Invalid HOTP hash fragment value.');
        }

        return str_pad((string) (($value & 0x7FFFFFFF) % self::MODULUS[$digits]), $digits, '0', STR_PAD_LEFT);
    }
}
