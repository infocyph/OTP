<?php

declare(strict_types=1);

use Infocyph\OTP\Support\SecretUtility;

test('Base32 decoding preserves RFC 4648 vectors and human input normalization', function () {
    foreach (['MY' => 'f', 'MZXQ' => 'fo', 'MZXW6' => 'foo', 'MZXW6YQ' => 'foob', 'MZXW6YTB' => 'fooba', 'MZXW6YTBOI' => 'foobar'] as $encoded => $binary) {
        expect(SecretUtility::decodeBase32($encoded))->toBe($binary)
            ->and(SecretUtility::decodeBase32(" \t".strtolower(implode('-', str_split($encoded, 2)))."===\r\n"))->toBe($binary);
    }
});

test('Base32 decoding rejects every nonzero trailing pad-bit pattern', function () {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    foreach ([16 => 2, 17 => 4, 18 => 1, 19 => 3] as $bytes => $padBits) {
        $encoded = str_repeat('A', (int) ceil($bytes * 8 / 5));
        expect(SecretUtility::requireStrongBase32($encoded))->toBe(str_repeat("\0", $bytes));
        for ($pattern = 1; $pattern < (1 << $padBits); $pattern++) {
            $noncanonical = substr($encoded, 0, -1).$alphabet[$pattern];
            expect(fn () => SecretUtility::decodeBase32($noncanonical))
                ->toThrow(InvalidArgumentException::class, 'Secret must use canonical Base32 encoding.');
        }
    }
});

test('Base32 decoding rejects malformed lengths and alphabet characters', function () {
    foreach (['A', 'AAA', 'AAAAAA', 'AA0A', 'AA=AA', "AA\0A"] as $secret) {
        expect(fn () => SecretUtility::decodeBase32($secret))->toThrow(InvalidArgumentException::class);
    }
});
