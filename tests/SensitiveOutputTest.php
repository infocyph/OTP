<?php

declare(strict_types=1);

use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\GridOTP;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\MobileOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Passkey;
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Tests\Support\CacheLayerState;
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


test('service diagnostic output redacts credentials and collaborator object graphs', function () {
    $cache = CacheLayerState::memory();
    $base32Secret = TOTP::generateSecret();
    $ocraKey = 'ocra-key-sentinel-1234567890';
    $genericKey = 'generic-key-sentinel-1234567890';
    $gridSecret = 'ABCDEFGH';
    $mobileSecret = '0123456789abcdef';
    $mobilePin = '9876';
    $recoveryKey = 'recovery-key-sentinel-1234567890';

    $services = [
        [new HOTP($base32Secret), [$base32Secret]],
        [new TOTP($base32Secret), [$base32Secret]],
        [new OCRA('OCRA-1:HOTP-SHA1-6:QN08', $ocraKey), [$ocraKey]],
        [new GenericOtp($cache, $genericKey), [$genericKey]],
        [new GridOTP($cache, $gridSecret), [$gridSecret]],
        [new MobileOTP($mobileSecret, $mobilePin), [$mobileSecret, $mobilePin]],
        [new RecoveryCodes(new InMemoryRecoveryCodeStore(), $recoveryKey), [$recoveryKey]],
    ];

    $dumpObject = \Closure::fromCallable('var_dump');
    $printObject = \Closure::fromCallable('print_r');

    foreach ($services as [$service, $sentinels]) {
        ob_start();
        $dumpObject($service);
        $dump = (string) ob_get_clean();
        $printed = (string) $printObject($service, true);

        foreach ($sentinels as $sentinel) {
            expect($dump)->not->toContain($sentinel)
                ->and($printed)->not->toContain($sentinel);
        }
    }

    if (Passkey::isAvailable()) {
        $passkey = new Passkey($cache, 'example.com', ['https://example.com']);
        ob_start();
        $dumpObject($passkey);
        $dump = (string) ob_get_clean();
        $printed = (string) $printObject($passkey, true);

        expect($dump)->not->toContain('authenticationStateLock')
            ->and($printed)->not->toContain('authenticationStateLock');
    }
});
