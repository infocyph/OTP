<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SecretUtility;
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

test('Recovery code generation rejects insufficient unique code space', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());

    expect(fn () => $codes->generate('user-1', count: 2, length: 6, characterSet: 'A'))
        ->toThrow(InvalidArgumentException::class);
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

test('otpauth URI parser rejects malformed numeric parameters', function () {
    $baseUri = 'otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP';

    foreach (['&digits=invalid', '&digits=3', '&period=0', '&counter=-1'] as $parameter) {
        expect(fn () => ProvisioningUriParser::parse($baseUri . $parameter))
            ->toThrow(InvalidArgumentException::class);
    }
});

test('verification windows reject negative bounds when constructed', function () {
    expect(fn () => new VerificationWindow(-1, 0))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new VerificationWindow(51, 50))
        ->toThrow(InvalidArgumentException::class);
});

test('HOTP and TOTP reject malformed codes without exception control flow', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);
    $hotp = new HOTP($secret);

    expect($totp->verify('invalid'))->toBeFalse()
        ->and($totp->verifyWithWindow('123')->reason)->toBe('malformed')
        ->and($hotp->verify('invalid', 0))->toBeFalse()
        ->and($hotp->verifyWithResult('123', 0)->reason)->toBe('malformed');
});

test('verification work and replay configuration are bounded', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);
    $hotp = new HOTP($secret);
    $store = new InMemoryReplayStore();

    expect(fn () => $hotp->verify(str_repeat('0', 6), 0, 101))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->verifyWithWindow($totp->getOTP(), replayStore: $store))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new TOTP($secret, period: 86401))
        ->toThrow(InvalidArgumentException::class);
});

test('Base32 secrets must be decodable and canonical', function () {
    expect(SecretUtility::isValidBase32('A'))->toBeFalse()
        ->and(SecretUtility::isValidBase32('MZ'))->toBeFalse()
        ->and(SecretUtility::isValidBase32('MY'))->toBeTrue();
});

test('recovery code configuration is bounded and normalizes custom alphabets', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), hashKey: str_repeat('k', 32));
    $generated = $codes->generate('user-1', count: 2, length: 6, characterSet: 'ab');

    expect($generated->plainCodes)->each->toMatch('/^[AB-]+$/')
        ->and($codes->consume('user-1', strtolower($generated->plainCodes[0]))->consumed)->toBeTrue()
        ->and(fn () => new RecoveryCodes(new InMemoryRecoveryCodeStore(), 'xxh128'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $codes->generate('user-1', count: 101))
        ->toThrow(InvalidArgumentException::class);
});

test('otpauth parser rejects ambiguous identities and duplicate parameters', function () {
    $secret = 'JBSWY3DPEHPK3PXP';

    expect(fn () => ProvisioningUriParser::parse(
        'otpauth://totp/IssuerA:user?secret=' . $secret . '&issuer=IssuerB',
    ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://totp/Issuer:user?secret=' . $secret . '&secret=' . $secret,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
        'otpauth://hotp/Issuer:user?secret=' . $secret,
        ))->toThrow(InvalidArgumentException::class);
});

test('otpauth provisioning rejects type-conflicting and reserved parameters', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);

    expect(fn () => ProvisioningUriParser::parse(
        'otpauth://totp/Issuer:user?secret=' . $secret . '&counter=0',
    ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://hotp/Issuer:user?secret=' . $secret . '&counter=0&period=30',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => ProvisioningUriParser::parse(
            'otpauth://ocra/Issuer:user?secret=' . $secret . '&ocraSuite=OCRA-1:HOTP-SHA256-8:QN08-invalid',
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->getProvisioningUri(
            'user',
            'Issuer',
            additionalParameters: ['secret' => $secret],
        ))->toThrow(InvalidArgumentException::class);
});

test('atomic in-memory replay state advances monotonically and validates TTLs', function () {
    $store = new InMemoryReplayStore();

    expect($store->advance('hotp:last_counter', 'device-1', 5))->toBeTrue()
        ->and($store->advance('hotp:last_counter', 'device-1', 5))->toBeFalse()
        ->and($store->advance('hotp:last_counter', 'device-1', 4))->toBeFalse()
        ->and($store->advance('hotp:last_counter', 'device-1', 6))->toBeTrue()
        ->and(fn () => $store->markConsumed('totp:step', 'user-1', '1', 0))
        ->toThrow(InvalidArgumentException::class);
});
