<?php

use Infocyph\OTP\HOTP;

test('Dynamic generation', function () {
    $secret = HOTP::generateSecret();
    $counter = 346;
    $hotp = new HOTP($secret);
    $otp = $hotp->getOTP($counter);
    expect($otp)->toBeString()
        ->and($otp)->toHaveLength(6)
        ->and(($hotp->verify($otp,$counter)))->toBeTrue();
});

test('Predefined generation', function () {
    $secret = 'GFZKEJSFNDSEZGG7K4C3UEYRWDF76LL5HD4HT73SDD6AE5EVRRH4OYPKIITGRH3MI2JUFZQX2GJNG66FPEEJIHYFP736JVONA5M7J4A';
    $counter = 5;
    $hotp = new HOTP($secret);
    $otp = $hotp->getOTP($counter);
    expect($otp)->toBeString()
        ->and($otp)->toHaveLength(6)->toBe('201774')
        ->and(($hotp->verify($otp,$counter)))->toBeTrue();
});
