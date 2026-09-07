<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\TOTP;


test('TOTP rotation preserves digits period and algorithm in replacement enrollment', function () {
    $current = TOTP::generateSecret();
    $next = TOTP::generateSecret();
    $rotation = (new TOTP($current, digits: 8, period: 60, algorithm: 'sha256'))
        ->planRotation($next, 'alice@example.com', 'Example', 60, 1_000);
    $parsed = ProvisioningUriParser::parse($rotation->nextEnrollment?->uri ?? '');

    expect($rotation->currentSecret)->toBe($current)
        ->and($rotation->nextSecret)->toBe($next)
        ->and($rotation->overlapUntil?->getTimestamp())->toBe(1_060)
        ->and($parsed->type)->toBe('totp')
        ->and($parsed->secret)->toBe($next)
        ->and($parsed->algorithm)->toBe('sha256')
        ->and($parsed->digits)->toBe(8)
        ->and($parsed->period)->toBe(60);
});

test('HOTP rotation preserves algorithm digits and replacement counter', function () {
    $current = HOTP::generateSecret();
    $next = HOTP::generateSecret();
    $rotation = (new HOTP($current, digits: 8, algorithm: 'sha256'))
        ->planRotation($next, 'alice@example.com', 'Example', initialCounter: 42);
    $parsed = ProvisioningUriParser::parse($rotation->nextEnrollment?->uri ?? '');

    expect($parsed->type)->toBe('hotp')
        ->and($parsed->secret)->toBe($next)
        ->and($parsed->algorithm)->toBe('sha256')
        ->and($parsed->digits)->toBe(8)
        ->and($parsed->counter)->toBe(42);
});

test('OCRA rotation preserves the complete authoritative suite', function () {
    $suite = 'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1';
    $current = OCRA::generateSecret(32);
    $next = OCRA::generateSecret(32);
    $rotation = OCRA::fromBase32($suite, $current)
        ->planRotation($next, 'alice@example.com', 'Example');
    $parsed = ProvisioningUriParser::parse($rotation->nextEnrollment?->uri ?? '');

    expect($parsed->type)->toBe('ocra')
        ->and($parsed->secret)->toBe($next)
        ->and($parsed->ocraSuite)->toBe($suite)
        ->and($parsed->algorithm)->toBe('sha256')
        ->and($parsed->digits)->toBe(8);
});
