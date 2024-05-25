<?php

use Infocyph\OTP\OTP;

test('Basic', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60);
    $otp = $otpInstance->generate($signature);
    expect($otpInstance->verify($signature, $otp))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Duration', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 2);
    $otp = $otpInstance->generate($signature);
    sleep(2);
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Retry with persistent key', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2);
    $otp = $otpInstance->generate($signature);
    expect($otpInstance->verify($signature, $otp + 1, false))->toBeFalse();
    expect($otpInstance->verify($signature, $otp, false))->toBeTrue();
    $otpInstance->delete($signature);
});

test('Retry with non-persistent key (delete key if key name matches)', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP(4, 60, 2);
    $otp = $otpInstance->generate($signature);
    expect($otpInstance->verify($signature, $otp + 1))->toBeFalse();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
    $otpInstance->delete($signature);
});

test('Delete', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP();
    $otp = $otpInstance->generate($signature);
    $otpInstance->delete($signature);
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});

test('Flash', function () {
    $signature = random_bytes(3);
    $otpInstance = new OTP();
    $otp = $otpInstance->generate($signature);
    $otpInstance->flush();
    expect($otpInstance->verify($signature, $otp))->toBeFalse();
});
