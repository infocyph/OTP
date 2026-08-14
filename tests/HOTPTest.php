<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\VerificationReason;

const RFC_4226_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('full RFC 4226 HOTP vector matrix', function () {
    $hotp = new HOTP(RFC_4226_SECRET);
    $expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

    foreach ($expected as $counter => $otp) {
        expect($hotp->generate($counter))->toBe($otp);
    }
});

test('HOTP look-ahead returns explicit progression and enforces monotonic replay', function () {
    $hotp = new HOTP(RFC_4226_SECRET);
    $cache = CacheLayerState::memory();
    $otp = $hotp->generate(8);
    $result = $hotp->verifyWithResult($otp, 5, 5, $cache, 'factor-v1');

    expect($result->matched)->toBeTrue()
        ->and($result->reason)->toBe(VerificationReason::Resynchronized)
        ->and($result->matchedCounter)->toBe(8)
        ->and($result->nextCounter)->toBe(9)
        ->and($hotp->verifyWithResult($otp, 5, 5, $cache, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(7), 7, 0, $cache, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(9), 9, 0, $cache, 'factor-v1')->matched)->toBeTrue();
});

test('HOTP validates configuration before malformed credentials', function () {
    $hotp = new HOTP(RFC_4226_SECRET);

    expect(fn () => new HOTP(RFC_4226_SECRET, 5))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new HOTP(RFC_4226_SECRET, 10))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new HOTP('JBSWY3DPEHPK3PXP'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $hotp->verifyWithResult('bad', -1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $hotp->verifyWithResult('bad', 0, 101))->toThrow(InvalidArgumentException::class)
        ->and($hotp->verifyWithResult('bad', 0)->reason)->toBe(VerificationReason::Malformed)
        ->and($hotp->generate(PHP_INT_MAX))->toHaveLength(6);
});

test('HOTP verifies exact and end-of-window counters through the maximum look-ahead', function () {
    $hotp = new HOTP(RFC_4226_SECRET);

    expect($hotp->verifyWithResult($hotp->generate(0), 0, 0)->matchedCounter)->toBe(0)
        ->and($hotp->verifyWithResult($hotp->generate(1), 0, 1)->matchedCounter)->toBe(1)
        ->and($hotp->verifyWithResult($hotp->generate(100), 0, 100)->matchedCounter)->toBe(100)
        ->and($hotp->verifyWithResult($hotp->generate(100), 0, 99)->matched)->toBeFalse();

    $exhausted = $hotp->verifyWithResult($hotp->generate(PHP_INT_MAX), PHP_INT_MAX);
    expect($exhausted->matched)->toBeTrue()
        ->and($exhausted->matchedCounter)->toBe(PHP_INT_MAX)
        ->and($exhausted->nextCounter)->toBeNull();
});

test('HOTP provisioning always includes its explicit initial counter', function () {
    $hotp = new HOTP(RFC_4226_SECRET);
    $uri = $hotp->getProvisioningUri('alice@example.com', 'Example', 3);

    expect($uri)->toContain('counter=3')
        ->not->toContain('algorithm=')
        ->not->toContain('digits=');
});

test('HOTP monotonic state survives CacheLayer reconstruction', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-hotp-');
    expect($path)->toBeString();
    $hotp = new HOTP(RFC_4226_SECRET);
    $cache = CacheLayerState::sqlite($path);

    expect($hotp->verifyWithResult($hotp->generate(13), 10, 3, $cache, 'factor-v1')->matched)
        ->toBeTrue();

    $cache = CacheLayerState::sqlite($path);
    expect($hotp->verifyWithResult($hotp->generate(13), 13, cache: $cache, factorId: 'factor-v1')->replayDetected)
        ->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(12), 12, cache: $cache, factorId: 'factor-v1')->replayDetected)
        ->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(14), 14, cache: $cache, factorId: 'factor-v1')->matched)
        ->toBeTrue();

    unlink($path);
});
