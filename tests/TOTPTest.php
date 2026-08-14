<?php

declare(strict_types=1);

use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\Tests\Support\SqliteAtomicStore;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use Infocyph\OTP\VerificationReason;
use ParagonIE\ConstantTime\Base32;

test('full RFC 6238 TOTP vector matrix', function () {
    $vectors = [
        59 => ['94287082', '46119246', '90693936'],
        1_111_111_109 => ['07081804', '68084774', '25091201'],
        1_111_111_111 => ['14050471', '67062674', '99943326'],
        1_234_567_890 => ['89005924', '91819424', '93441116'],
        2_000_000_000 => ['69279037', '90698825', '38618901'],
        20_000_000_000 => ['65353130', '77737706', '47863826'],
    ];
    $authenticators = [
        new TOTP(rtrim(Base32::encodeUpper('12345678901234567890'), '='), 8, 30, 'sha1'),
        new TOTP(rtrim(Base32::encodeUpper('12345678901234567890123456789012'), '='), 8, 30, 'sha256'),
        new TOTP(rtrim(Base32::encodeUpper('1234567890123456789012345678901234567890123456789012345678901234'), '='), 8, 30, 'sha512'),
    ];

    foreach ($vectors as $timestamp => $expected) {
        foreach ($authenticators as $index => $totp) {
            expect($totp->generate($timestamp))->toBe($expected[$index]);
        }
    }
});

test('TOTP keeps current-past-future search order and monotonic replay state', function () {
    $totp = new TOTP(TOTP::generateSecret());
    $store = new InMemoryReplayStore();
    $step100Time = 3000;
    $window = new VerificationWindow(1, 1);

    $future = $totp->verifyWithWindow($totp->generate(3030), $step100Time, $window, $store, 'factor-v1');
    $old = $totp->verifyWithWindow($totp->generate(3000), $step100Time, $window, $store, 'factor-v1');
    $new = $totp->verifyWithWindow($totp->generate(3060), 3060, $window, $store, 'factor-v1');

    expect($future->matched)->toBeTrue()
        ->and($future->reason)->toBe(VerificationReason::Drifted)
        ->and($old->replayDetected)->toBeTrue()
        ->and($totp->verifyWithWindow($totp->generate(3030), 3030, $window, $store, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($new->matched)->toBeTrue();
});

test('TOTP validates protocol bounds and time helpers', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);

    expect($totp->getCurrentTimeStep(60))->toBe(2)
        ->and($totp->getRemainingSeconds(60))->toBe(30)
        ->and(fn () => $totp->getTimeStepFromTimestamp(-1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new TOTP($secret, 5))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new TOTP($secret, 10))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->verifyWithWindow('bad', replayStore: new InMemoryReplayStore()))
        ->toThrow(InvalidArgumentException::class);
});

test('concurrent TOTP verification advances replay state only once', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-replay-');
    expect($path)->toBeString();
    $secret = TOTP::generateSecret();
    $timestamp = 3_000;
    $code = (new TOTP($secret))->generate($timestamp);
    new SqliteAtomicStore($path);

    $results = Concurrency::run(static function () use ($path, $secret, $timestamp, $code): int {
        $result = (new TOTP($secret))->verifyWithWindow(
            $code,
            $timestamp,
            new VerificationWindow(),
            new SqliteAtomicStore($path),
            'factor-concurrent',
        );

        return $result->matched ? 1 : 0;
    });
    sort($results);

    expect($results)->toBe([0, 1]);
    unlink($path);
});
