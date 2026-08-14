<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\TOTP;
use ParagonIE\ConstantTime\Base32;

test('TOTP, HOTP, and OCRA provisioning round-trip effective configuration', function () {
    $totp = new TOTP(TOTP::generateSecret(), 8, 60, 'sha256');
    $hotp = new HOTP(HOTP::generateSecret(), 7, 'sha512');
    $ocra = OCRA::fromBase32('OCRA-1:HOTP-SHA256-8:QN08', OCRA::generateSecret(32));

    $parsedTotp = ProvisioningUriParser::parse($totp->getProvisioningUri('alice@example.com', 'Example', ['tenant' => 'north']));
    $parsedHotp = ProvisioningUriParser::parse($hotp->getProvisioningUri('alice@example.com', 'Example', 9));
    $parsedOcra = ProvisioningUriParser::parse($ocra->getProvisioningUri('alice@example.com', 'Example'));

    foreach ([$parsedTotp, $parsedHotp, $parsedOcra] as $parsed) {
        $rebuilt = ProvisioningUriBuilder::build(
            $parsed->type,
            $parsed->secret,
            $parsed->label,
            $parsed->issuer ?? '',
            [
                'algorithm' => $parsed->algorithm !== 'sha1' || $parsed->type === 'ocra',
                'digits' => $parsed->digits !== 6 || $parsed->type === 'ocra',
                'period' => $parsed->type === 'totp' && $parsed->period !== 30,
                'counter' => $parsed->type === 'hotp',
            ],
            $parsed->additionalParameters,
            $parsed->algorithm,
            $parsed->digits,
            $parsed->period,
            $parsed->counter,
            $parsed->ocraSuite,
        );
        expect(ProvisioningUriParser::parse($rebuilt))->toEqual($parsed);
    }

    expect($parsedTotp->algorithm)->toBe('sha256')
        ->and($parsedTotp->digits)->toBe(8)
        ->and($parsedTotp->period)->toBe(60)
        ->and($parsedTotp->additionalParameters)->toBe(['tenant' => 'north'])
        ->and($parsedHotp->counter)->toBe(9)
        ->and($parsedHotp->algorithm)->toBe('sha512')
        ->and($parsedOcra->algorithm)->toBe('sha256')
        ->and($parsedOcra->digits)->toBe(8);
});

test('default TOTP provisioning is minimal and parser supplies effective defaults', function () {
    $uri = (new TOTP(TOTP::generateSecret()))->getProvisioningUri('alice@example.com', 'Example');
    $parsed = ProvisioningUriParser::parse($uri);

    expect($uri)->not->toContain('algorithm=')
        ->not->toContain('digits=')
        ->not->toContain('period=')
        ->and($parsed->algorithm)->toBe('sha1')
        ->and($parsed->digits)->toBe(6)
        ->and($parsed->period)->toBe(30);
});

test('provisioning rejects reserved collisions, identity ambiguity, and excessive labels', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);
    $maximumCombinedLabel = $totp->getProvisioningUri(str_repeat('a', 127), str_repeat('i', 127));

    expect($maximumCombinedLabel)->toContain(rawurlencode(str_repeat('i', 127) . ':' . str_repeat('a', 127)))
        ->and(fn () => $totp->getProvisioningUri(str_repeat('a', 127), str_repeat('i', 128)))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->getProvisioningUri('alice', 'Bad:Issuer'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->getProvisioningUri('Issuer:alice', 'Issuer'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->getProvisioningUri(str_repeat('a', 200), str_repeat('i', 100)))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->getProvisioningUri('alice', 'Issuer', ['Secret' => 'x']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Issuer:alice?secret=' . $secret . '&ISSUER=Issuer',
        ))->toThrow(InvalidArgumentException::class);
});

test('parser rejects duplicate and protocol-conflicting parameters', function () {
    $secret = TOTP::generateSecret();
    $suite = rawurlencode('OCRA-1:HOTP-SHA256-8:QN08');

    expect(fn () => ProvisioningUriParser::parse(
        'otpauth://totp/Issuer:alice?secret=' . $secret . '&secret=' . $secret,
    ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://hotp/Issuer:alice?secret=' . $secret,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://ocra/Issuer:alice?secret=' . $secret . '&algorithm=SHA1&ocraSuite=' . $suite,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://ocra/Issuer:alice?secret=' . $secret . '&digits=6&ocraSuite=' . $suite,
        ))->toThrow(InvalidArgumentException::class);
});

test('low-level provisioning builder also always emits HOTP counter', function () {
    $uri = ProvisioningUriBuilder::build(
        'hotp',
        HOTP::generateSecret(),
        'alice',
        'Example',
        [],
        counter: 0,
    );

    expect($uri)->toContain('counter=0');
});

test('provisioning enforces factor-strength secret bounds on build and parse', function () {
    $weak = rtrim(Base32::encodeUpper(str_repeat('w', 15)), '=');
    $oversized = rtrim(Base32::encodeUpper(str_repeat('o', 1025)), '=');

    expect(fn () => ProvisioningUriBuilder::build('totp', $weak, 'alice', 'Example', []))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:alice?secret=' . $weak . '&issuer=Example',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriBuilder::build('totp', $oversized, 'alice', 'Example', []))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:alice?secret=' . $oversized . '&issuer=Example',
        ))->toThrow(InvalidArgumentException::class);
});

test('parser applies account-label and extension bounds symmetrically', function () {
    $secret = TOTP::generateSecret();
    $withoutLabelIssuer = ProvisioningUriParser::parse(
        'otpauth://totp/:alice?secret=' . $secret,
    );
    $unicode = ProvisioningUriParser::parse(
        'otpauth://totp/Example:' . rawurlencode(' ব্যবহারকারী ') . '?secret=' . $secret . '&issuer=Example',
    );

    expect($withoutLabelIssuer->issuer)->toBeNull()
        ->and($withoutLabelIssuer->label)->toBe('alice')
        ->and($unicode->label)->toBe('ব্যবহারকারী')
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:alice:extra?secret=' . $secret . '&issuer=Example',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:?secret=' . $secret . '&issuer=Example',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:alice?secret=' . $secret . '&' . str_repeat('k', 65) . '=value',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Example:alice?secret=' . $secret . '&extension=' . str_repeat('v', 1025),
        ))->toThrow(InvalidArgumentException::class);
});
