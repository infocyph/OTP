<?php

declare(strict_types=1);

use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\SecretRotation;
use ParagonIE\ConstantTime\Base32;

test('secret rotation uses one typed operation and normalizes zero grace', function () {
    $totp = new TOTP(TOTP::generateSecret(), algorithm: 'sha256');
    $zero = $totp->planRotation(TOTP::generateSecret(), 'alice', 'Example', 0, 1000);
    $positive = $totp->planRotation(TOTP::generateSecret(), 'alice', 'Example', 60, 1000);

    expect($zero->requiresImmediateCutover())->toBeTrue()
        ->and($zero->overlapUntil)->toBeNull()
        ->and($positive->hasGracePeriod())->toBeTrue()
        ->and($positive->isDualSecretActive(new DateTimeImmutable('@1059')))->toBeTrue()
        ->and($positive->isDualSecretActive(new DateTimeImmutable('@1060')))->toBeFalse();
});

test('secret rotation rejects invalid, weak, same, and negative inputs', function () {
    $secret = TOTP::generateSecret();
    $nextSecret = TOTP::generateSecret();
    $totp = new TOTP($secret);

    expect(fn () => $totp->planRotation($secret, 'alice', 'Example'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->planRotation('not-base32!', 'alice', 'Example'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->planRotation('JBSWY3DPEHPK3PXP', 'alice', 'Example'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->planRotation(
            rtrim(Base32::encodeUpper(str_repeat('o', 1025)), '='),
            'alice',
            'Example',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->planRotation(TOTP::generateSecret(), 'alice', 'Example', -1))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new SecretRotation(
            $secret,
            $nextSecret,
            nextEnrollment: new EnrollmentPayload(TOTP::generateSecret(), 'otpauth://totp/example', 'Example', 'alice'),
        ))->toThrow(InvalidArgumentException::class, 'replacement secret');
});
