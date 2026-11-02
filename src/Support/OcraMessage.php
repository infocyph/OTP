<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\ValueObjects\OcraSuite;
use InvalidArgumentException;
use RuntimeException;

/** @internal RFC 6287 binary message encoding for a validated suite and inputs. */
final class OcraMessage
{
    /**
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     */
    public static function build(OcraSuite $suite, string $challenge, array $operation): string
    {
        $message = $suite->suite . "\0";
        if ($operation['counter'] !== null) {
            $message .= self::packInteger($operation['counter']);
        }
        $message .= self::encodeChallenge($suite, $challenge);
        $message .= $operation['pinDigest'] ?? '';
        $message .= $operation['session'] ?? '';
        if ($operation['timestamp'] !== null && $suite->timeStepSeconds !== null) {
            $message .= self::packInteger(intdiv($operation['timestamp'], $suite->timeStepSeconds));
        }

        return $message;
    }

    public static function hexToBytes(string $hex): string
    {
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }

        $bytes = hex2bin($hex);
        if ($bytes === false) {
            throw new InvalidArgumentException('Invalid hexadecimal input.');
        }

        return $bytes;
    }

    private static function decimalToBinary(string $decimal): string
    {
        $decimal = ltrim($decimal, '0');
        if ($decimal === '') {
            return "\0";
        }

        $hex = '';
        while ($decimal !== '') {
            $quotient = '';
            $remainder = 0;
            $length = strlen($decimal);
            for ($index = 0; $index < $length; $index++) {
                $value = ($remainder * 10) + (ord($decimal[$index]) - 48);
                $digit = intdiv($value, 16);
                if ($quotient !== '' || $digit !== 0) {
                    $quotient .= (string) $digit;
                }
                $remainder = $value % 16;
            }

            $hex = dechex($remainder) . $hex;
            $decimal = $quotient;
        }

        return self::hexToBytes($hex);
    }

    private static function encodeChallenge(OcraSuite $suite, string $challenge): string
    {
        $bytes = match ($suite->challengeFormat) {
            'n' => self::decimalToBinary($challenge),
            'a' => $challenge,
            'h' => self::hexToBytes($challenge),
            default => throw new RuntimeException('Invalid parsed OCRA challenge format.'),
        };

        return str_pad($bytes, 128, "\0");
    }

    private static function packInteger(int $value): string
    {
        return pack('NN', ($value >> 32) & 0xFFFFFFFF, $value & 0xFFFFFFFF);
    }
}
