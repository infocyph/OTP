<?php

use Infocyph\OTP\HOTP;
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\VerificationWindow;

test('TOTP supports asymmetric verification windows and helper metadata', function () {
    $secret = 'DZJCKBRRJVSXNTALRREMD6ZCCMNEBP53Q424XLMVN6AOL6MCNIEUGK54OEQVXQXHQFGI3UHBBSLNXUYHW2QQNV2BLZD2QNOKTRL3WSI';
    $totp = new TOTP($secret);
    $baseTime = 1716532624;
    $nextWindowOtp = $totp->getOTP($baseTime + 30);

    $result = $totp->verifyWithWindow(
        $nextWindowOtp,
        $baseTime,
        new VerificationWindow(0, 1),
    );

    expect($result->matched)->toBeTrue()
        ->and($result->driftOffset)->toBe(1)
        ->and($result->isDrifted())->toBeTrue()
        ->and($result->matchedTimestep)->toBe($totp->getCurrentTimeStep($baseTime) + 1)
        ->and($totp->getRemainingSeconds($baseTime))->toBe(26);
});

test('TOTP replay protection rejects the same timestep twice', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);
    $store = new InMemoryReplayStore();
    $timestamp = 1716532624;
    $otp = $totp->getOTP($timestamp);

    $first = $totp->verifyWithWindow($otp, $timestamp, new VerificationWindow(), $store, 'user-1');
    $second = $totp->verifyWithWindow($otp, $timestamp, new VerificationWindow(), $store, 'user-1');

    expect($first->matched)->toBeTrue()
        ->and($second->matched)->toBeFalse()
        ->and($second->replayDetected)->toBeTrue();
});

test('HOTP look-ahead verification reports matched counter and blocks replay', function () {
    $secret = HOTP::generateSecret();
    $hotp = new HOTP($secret);
    $store = new InMemoryReplayStore();
    $otp = $hotp->getOTP(8);

    $result = $hotp->verifyWithResult($otp, 5, 5, $store, 'device-1');
    $replay = $hotp->verifyWithResult($otp, 5, 5, $store, 'device-1');

    expect($result->matched)->toBeTrue()
        ->and($result->matchedCounter)->toBe(8)
        ->and($replay->matched)->toBeFalse()
        ->and($replay->replayDetected)->toBeTrue();
});

test('Recovery codes can be generated, consumed once, and regenerated', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());
    $generated = $codes->generate('user-1', count: 8, length: 8, groupSize: 4);

    $first = $codes->consume('user-1', $generated->plainCodes[0]);
    $second = $codes->consume('user-1', $generated->plainCodes[0]);
    $regenerated = $codes->generate('user-1', count: 10, length: 10);

    expect($generated->totalGenerated)->toBe(8)
        ->and($first->consumed)->toBeTrue()
        ->and($first->remainingCount)->toBe(7)
        ->and($second->consumed)->toBeFalse()
        ->and($regenerated->totalGenerated)->toBe(10)
        ->and($regenerated->remainingCount)->toBe(10);
});

test('otpauth URIs round-trip through parser with issuer-safe labels', function () {
    $secret = TOTP::generateSecret();
    $totp = (new TOTP($secret))->setAlgorithm('sha256');
    $uri = $totp->getProvisioningUri('user@example.com', 'Example App');
    $parsed = ProvisioningUriParser::parse($uri);

    expect($parsed->type)->toBe('totp')
        ->and($parsed->issuer)->toBe('Example App')
        ->and($parsed->label)->toBe('user@example.com')
        ->and($parsed->algorithm)->toBe('sha256')
        ->and($parsed->period)->toBe(30);
});
