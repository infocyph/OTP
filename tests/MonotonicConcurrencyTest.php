<?php

declare(strict_types=1);

use Infocyph\OTP\HOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;


test('SQLite lock fallback never regresses TOTP state in an out-of-order race', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-totp-order-');
    expect($path)->toBeString();
    CacheLayerState::sqlite($path);
    $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    $totp = new TOTP($secret);
    $lowTime = 3_000;
    $highTime = 3_030;
    $lowCode = $totp->generate($lowTime);
    $highCode = $totp->generate($highTime);

    $results = Concurrency::run(static function (int $worker) use ($path, $secret, $lowTime, $highTime, $lowCode, $highCode): int {
        $result = (new TOTP($secret))->verifyWithWindow(
            $worker === 0 ? $lowCode : $highCode,
            $worker === 0 ? $lowTime : $highTime,
            cache: CacheLayerState::sqlite($path),
            factorId: 'ordered-totp',
        );

        return $result->matched ? $worker + 1 : 0;
    });

    expect($results)->toContain(2);
    $cache = CacheLayerState::sqlite($path);
    expect($totp->verifyWithWindow($lowCode, $lowTime, cache: $cache, factorId: 'ordered-totp')->replayDetected)
        ->toBeTrue()
        ->and($totp->verifyWithWindow($highCode, $highTime, cache: $cache, factorId: 'ordered-totp')->replayDetected)
        ->toBeTrue();

    unlink($path);
});

test('SQLite lock fallback never regresses HOTP state in an adjacent-counter race', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-hotp-order-');
    expect($path)->toBeString();
    CacheLayerState::sqlite($path);
    $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    $hotp = new HOTP($secret);
    $lowCode = $hotp->generate(4);
    $highCode = $hotp->generate(5);

    $results = Concurrency::run(static function (int $worker) use ($path, $secret, $lowCode, $highCode): int {
        $counter = $worker === 0 ? 4 : 5;
        $result = (new HOTP($secret))->verifyWithResult(
            $worker === 0 ? $lowCode : $highCode,
            $counter,
            cache: CacheLayerState::sqlite($path),
            factorId: 'ordered-hotp',
        );

        return $result->matched ? $worker + 1 : 0;
    });

    expect($results)->toContain(2);
    $cache = CacheLayerState::sqlite($path);
    expect($hotp->verifyWithResult($lowCode, 4, cache: $cache, factorId: 'ordered-hotp')->replayDetected)
        ->toBeTrue()
        ->and($hotp->verifyWithResult($highCode, 5, cache: $cache, factorId: 'ordered-hotp')->replayDetected)
        ->toBeTrue();

    unlink($path);
});

test('SQLite lock fallback never regresses counter OCRA state', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-ocra-order-');
    expect($path)->toBeString();
    CacheLayerState::sqlite($path);
    $suite = 'OCRA-1:HOTP-SHA256-8:C-QN08';
    $key = '12345678901234567890123456789012';
    $ocra = new OCRA($suite, $key);
    $lowCode = $ocra->generate('12345678', 4);
    $highCode = $ocra->generate('12345678', 5);

    $results = Concurrency::run(static function (int $worker) use ($path, $suite, $key, $lowCode, $highCode): int {
        $counter = $worker === 0 ? 4 : 5;
        $result = (new OCRA($suite, $key))->verifyWithResult(
            $worker === 0 ? $lowCode : $highCode,
            '12345678',
            $counter,
            cache: CacheLayerState::sqlite($path),
            factorId: 'ordered-ocra',
        );

        return $result->matched ? $worker + 1 : 0;
    });

    expect($results)->toContain(2);
    $cache = CacheLayerState::sqlite($path);
    expect($ocra->verifyWithResult($lowCode, '12345678', 4, cache: $cache, factorId: 'ordered-ocra')->replayDetected)
        ->toBeTrue()
        ->and($ocra->verifyWithResult($highCode, '12345678', 5, cache: $cache, factorId: 'ordered-ocra')->replayDetected)
        ->toBeTrue();

    unlink($path);
});
