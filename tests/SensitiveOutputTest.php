<?php

declare(strict_types=1);

use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\TOTP;


test('enrollment payload debug output redacts secret-bearing fields', function () {
    $totp = new TOTP(TOTP::generateSecret());
    $payload = $totp->getEnrollmentPayload('user@example.com', 'Example', withQrSvg: true);
    $debug = $payload->__debugInfo();

    expect($debug['secret'])->toBe('[redacted]')
        ->and($debug['uri'])->toBe('[redacted]')
        ->and($debug['qrSvg'])->toBe('[redacted]')
        ->and(serialize($debug))->not->toContain($payload->secret)
        ->and(serialize($debug))->not->toContain($payload->uri);
});

test('parsed provisioning data debug output redacts the OTP secret', function () {
    $totp = new TOTP(TOTP::generateSecret());
    $parsed = ProvisioningUriParser::parse($totp->getProvisioningUri('user@example.com', 'Example'));
    $debug = $parsed->__debugInfo();

    expect($debug['secret'])->toBe('[redacted]')
        ->and(serialize($debug))->not->toContain($parsed->secret);
});

test('rotation debug output never exposes current or replacement secrets', function () {
    $current = TOTP::generateSecret();
    $next = TOTP::generateSecret();
    $rotation = (new TOTP($current))->planRotation($next, 'user@example.com', 'Example');
    $debug = $rotation->__debugInfo();

    expect($debug['currentSecret'])->toBe('[redacted]')
        ->and($debug['nextSecret'])->toBe('[redacted]')
        ->and(serialize($debug))->not->toContain($current)
        ->and(serialize($debug))->not->toContain($next);
});

test('recovery-code generation debug output redacts every plaintext code', function () {
    $result = (new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32)))
        ->generate('debug-user', count: 4);
    $debug = $result->__debugInfo();

    expect($debug['plainCodes'])->toBe('[redacted]');
    foreach ($result->plainCodes as $plainCode) {
        expect(serialize($debug))->not->toContain($plainCode);
    }
});
