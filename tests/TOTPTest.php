<?php

use Infocyph\OTP\TOTP;

test('Dynamic generation', function () {
    $secret = TOTP::generateSecret();
    $counter = 346;
    $hotp = new TOTP($secret);
    $otp = $hotp->getOTP($counter);
    expect($otp)->toBeString()
        ->and($otp)->toHaveLength(6)
        ->and(($hotp->verify($otp,$counter)))->toBeTrue();
});

test('Predefined generation', function () {
    $secret = 'DZJCKBRRJVSXNTALRREMD6ZCCMNEBP53Q424XLMVN6AOL6MCNIEUGK54OEQVXQXHQFGI3UHBBSLNXUYHW2QQNV2BLZD2QNOKTRL3WSI';
    $hotp = new TOTP($secret);
    $otp = $hotp->getOTP(1716532624);
    expect($otp)->toBeString()
        ->and($otp)->toHaveLength(6)->toBe('661688')
        ->and(($hotp->verify($otp,1716532624)))->toBeTrue();
});
