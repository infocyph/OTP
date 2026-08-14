<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\Stores\InMemoryReplayStore;
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
    $store = new InMemoryReplayStore();
    $otp = $hotp->generate(8);
    $result = $hotp->verifyWithResult($otp, 5, 5, $store, 'factor-v1');

    expect($result->matched)->toBeTrue()
        ->and($result->reason)->toBe(VerificationReason::Resynchronized)
        ->and($result->matchedCounter)->toBe(8)
        ->and($result->nextCounter)->toBe(9)
        ->and($hotp->verifyWithResult($otp, 5, 5, $store, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(7), 7, 0, $store, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($hotp->verifyWithResult($hotp->generate(9), 9, 0, $store, 'factor-v1')->matched)->toBeTrue();
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

test('HOTP provisioning always includes its explicit initial counter', function () {
    $hotp = new HOTP(RFC_4226_SECRET);
    $uri = $hotp->getProvisioningUri('alice@example.com', 'Example', 3);

    expect($uri)->toContain('counter=3')
        ->not->toContain('algorithm=')
        ->not->toContain('digits=');
});
