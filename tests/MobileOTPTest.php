<?php

declare(strict_types=1);

use Infocyph\OTP\MobileOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use Infocyph\OTP\VerificationReason;

test('MobileOTP matches the legacy counter secret pin construction', function () {
    $mobile = new MobileOTP('7ac61d4736f51a2b', '5555');

    expect($mobile->generate(1_234_567_890))->toBe('09cb10')
        ->and($mobile->getTimeStepFromTimestamp(1_234_567_890))->toBe(123_456_789);
});

test('MobileOTP verifies exact and drifted windows', function () {
    $mobile = new MobileOTP('7ac61d4736f51a2b', '5555');
    $timestamp = 1_234_567_890;
    $past = $mobile->generate($timestamp - MobileOTP::PERIOD);
    $future = $mobile->generate($timestamp + MobileOTP::PERIOD);

    expect($mobile->verify($past, $timestamp))->toBeFalse()
        ->and($mobile->verify($past, $timestamp, pastWindows: 1))->toBeTrue()
        ->and($mobile->verify($future, $timestamp, futureWindows: 1))->toBeTrue();

    $result = $mobile->verifyWithWindow($past, $timestamp, new VerificationWindow(1, 0));
    expect($result->matched)->toBeTrue()
        ->and($result->reason)->toBe(VerificationReason::Drifted)
        ->and($result->driftOffset)->toBe(-1);
});

test('MobileOTP supports explicit legacy clock offsets', function () {
    $mobile = new MobileOTP('7ac61d4736f51a2b', '5555');
    $timestamp = 1_234_567_890;
    $withOffset = $mobile->generate($timestamp, 360);

    expect($mobile->verify($withOffset, $timestamp, offsetSteps: 360))->toBeTrue()
        ->and($mobile->verify($withOffset, $timestamp))->toBeFalse();
});

test('MobileOTP replay-aware verification accepts a timestep once', function () {
    $cache = CacheLayerState::memory();
    $mobile = new MobileOTP('7ac61d4736f51a2b', '5555');
    $timestamp = 1_234_567_890;
    $otp = $mobile->generate($timestamp);

    $first = $mobile->verifyWithWindow(
        $otp,
        $timestamp,
        cache: $cache,
        factorId: 'user-42:mobile:v1',
    );
    $second = $mobile->verifyWithWindow(
        $otp,
        $timestamp,
        cache: $cache,
        factorId: 'user-42:mobile:v1',
    );

    expect($first->matched)->toBeTrue()
        ->and($second->matched)->toBeFalse()
        ->and($second->reason)->toBe(VerificationReason::Replay);
});

test('MobileOTP validates the legacy protocol bounds', function () {
    expect(fn () => new MobileOTP('short', '5555'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new MobileOTP('7ac61d4736f51a2b', '123'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new MobileOTP('7ac61d4736f51a2b', '12a4'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => (new MobileOTP('7ac61d4736f51a2b', '5555'))->generate(0, 8641))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => (new MobileOTP('7ac61d4736f51a2b', '5555'))->verifyWithWindow(
            '09cb10',
            1_234_567_890,
            new VerificationWindow(19, 0),
        ))->toThrow(InvalidArgumentException::class);
});

test('MobileOTP rejects malformed output before credential comparison', function () {
    $mobile = new MobileOTP('7ac61d4736f51a2b', '5555');

    expect($mobile->verify('ABCDEF', 1_234_567_890))->toBeFalse()
        ->and($mobile->verify('12345', 1_234_567_890))->toBeFalse()
        ->and($mobile->verifyWithWindow('ABCDEF', 1_234_567_890)->reason)
        ->toBe(VerificationReason::Malformed);
});

test('MobileOTP generates canonical 16 character init secrets', function () {
    $secret = MobileOTP::generateSecret();

    expect($secret)->toMatch('/\A[0-9a-f]{16}\z/D');
});
