<?php

use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\StepUp;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\DeviceEnrollment;

test('device enrollment tracks pending activation and revocation lifecycle', function () {
    $enrollment = DeviceEnrollment::create('device-1', 'Alice phone', 'secret-ref-1');

    $active = $enrollment->activate(new \DateTimeImmutable('2026-04-20 10:00:00'));
    $renamed = $active->rename('Primary phone');
    $rotated = $renamed->withSecretReference('secret-ref-2');
    $revoked = $rotated->revoke(new \DateTimeImmutable('2026-04-20 11:00:00'));

    expect($enrollment->isPendingActivation())->toBeTrue()
        ->and($active->isActive())->toBeTrue()
        ->and($renamed->label)->toBe('Primary phone')
        ->and($rotated->secretReference)->toBe('secret-ref-2')
        ->and($revoked->isRevoked())->toBeTrue()
        ->and($revoked->isActive())->toBeFalse();
});

test('step-up helpers report age and freshness details', function () {
    $verifiedAt = new \DateTimeImmutable('2026-04-20 10:00:00');
    $now = new \DateTimeImmutable('2026-04-20 10:04:00');

    $result = StepUp::assess($verifiedAt, 300, $now);

    expect($result->hasVerification())->toBeTrue()
        ->and($result->ageInSeconds)->toBe(240)
        ->and($result->isFresh())->toBeTrue()
        ->and($result->requiresFreshOtp)->toBeFalse()
        ->and($result->expiresAt?->format('Y-m-d H:i:s'))->toBe('2026-04-20 10:05:00')
        ->and(StepUp::requiresFreshOtp($verifiedAt, 120, $now))->toBeTrue();
});

test('totp secret rotation can prepare reprovisioning payloads', function () {
    $totp = (new TOTP(TOTP::generateSecret()))->setAlgorithm('sha256');
    $rotation = $totp->planSecretRotation(
        TOTP::generateSecret(),
        'alice@example.com',
        'Example App',
        gracePeriodInSeconds: 3600,
        now: 1716532624,
        withQrSvg: true,
    );

    expect($rotation->hasGracePeriod())->toBeTrue()
        ->and($rotation->isDualSecretActive(new \DateTimeImmutable('@1716533000')))->toBeTrue()
        ->and($rotation->nextEnrollment?->issuer)->toBe('Example App')
        ->and($rotation->nextEnrollment?->label)->toBe('alice@example.com')
        ->and($rotation->nextEnrollment?->qrSvg)->toContain('<svg');
});

test('hotp and ocra secret rotation can prepare replacement enrollment payloads', function () {
    $hotp = (new HOTP(HOTP::generateSecret()))->setAlgorithm('sha512')->setCounter(5);
    $hotpRotation = $hotp->planSecretRotation(
        HOTP::generateSecret(),
        'alice@example.com',
        'Example App',
    );

    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', '12345678901234567890123456789012');
    $ocraRotation = $ocra->planSecretRotation(
        OCRA::generateSecret(),
        'alice@example.com',
        'Example App',
        gracePeriodInSeconds: 900,
        now: 1716532624,
    );

    expect($hotpRotation->requiresImmediateCutover())->toBeTrue()
        ->and($hotpRotation->nextEnrollment?->uri)->toContain('counter=5')
        ->and($ocraRotation->hasGracePeriod())->toBeTrue()
        ->and($ocraRotation->nextEnrollment?->uri)->toContain('ocraSuite=');
});
