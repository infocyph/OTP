<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
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
    $cache = CacheLayerState::memory();
    $step100Time = 3000;
    $window = new VerificationWindow(1, 1);

    $future = $totp->verifyWithWindow($totp->generate(3030), $step100Time, $window, $cache, 'factor-v1');
    $old = $totp->verifyWithWindow($totp->generate(3000), $step100Time, $window, $cache, 'factor-v1');
    $new = $totp->verifyWithWindow($totp->generate(3060), 3060, $window, $cache, 'factor-v1');

    expect($future->matched)->toBeTrue()
        ->and($future->reason)->toBe(VerificationReason::Drifted)
        ->and($old->replayDetected)->toBeTrue()
        ->and($totp->verifyWithWindow($totp->generate(3030), 3030, $window, $cache, 'factor-v1')->replayDetected)->toBeTrue()
        ->and($new->matched)->toBeTrue();
});

test('TOTP enforces the complete monotonic sequence and maximum drift boundaries', function () {
    $totp = new TOTP(TOTP::generateSecret());
    $cache = CacheLayerState::memory();
    $window = new VerificationWindow(1, 1);

    expect($totp->verifyWithWindow($totp->generate(3000), 3000, $window, $cache, 'factor-sequence')->matched)
        ->toBeTrue()
        ->and($totp->verifyWithWindow($totp->generate(3000), 3000, $window, $cache, 'factor-sequence')->replayDetected)
        ->toBeTrue()
        ->and($totp->verifyWithWindow($totp->generate(2970), 3000, $window, $cache, 'factor-sequence')->replayDetected)
        ->toBeTrue()
        ->and($totp->verifyWithWindow($totp->generate(3030), 3000, $window, $cache, 'factor-sequence')->matched)
        ->toBeTrue()
        ->and($totp->verifyWithWindow(
            $totp->generate(1500),
            3000,
            new VerificationWindow(50),
        )->driftOffset)->toBe(-50)
        ->and($totp->verifyWithWindow(
            $totp->generate(4500),
            3000,
            new VerificationWindow(0, 50),
        )->driftOffset)->toBe(50);
});

test('TOTP validates protocol bounds and time helpers', function () {
    $secret = TOTP::generateSecret();
    $totp = new TOTP($secret);

    expect($totp->getCurrentTimeStep(60))->toBe(2)
        ->and($totp->getRemainingSeconds(60))->toBe(30)
        ->and(fn () => $totp->getTimeStepFromTimestamp(-1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new TOTP($secret, 5))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new TOTP($secret, 10))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $totp->verifyWithWindow('bad', cache: CacheLayerState::memory()))
        ->toThrow(InvalidArgumentException::class);
});

test('concurrent TOTP verification advances replay state only once', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-replay-');
    expect($path)->toBeString();
    $secret = TOTP::generateSecret();
    $timestamp = 3_000;
    $code = (new TOTP($secret))->generate($timestamp);
    CacheLayerState::sqlite($path);

    $results = Concurrency::run(static function () use ($path, $secret, $timestamp, $code): int {
        $cache = CacheLayerState::sqlite($path);
        $result = (new TOTP($secret))->verifyWithWindow(
            $code,
            $timestamp,
            new VerificationWindow(),
            $cache,
            'factor-concurrent',
        );

        return $result->matched ? 1 : 0;
    });
    sort($results);

    expect($results)->toBe([0, 1]);
    unlink($path);
});

test('TOTP replay state TTL covers the complete verification window', function () {
    $totp = new TOTP(TOTP::generateSecret(), period: 30);
    $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $cache->method('get')->willReturn(null);
    $cache->expects($this->once())->method('set')->with(
        $this->callback(static fn (string $key): bool => strlen($key) === 64),
        100,
        90,
    )->willReturn(true);

    $result = $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        new VerificationWindow(1, 1),
        $cache,
        'factor-v1',
    );

    expect($result->matched)->toBeTrue();
});

test('TOTP replay TTL covers every accepted window shape', function (int $past, int $future, int $ttl) {
    $totp = new TOTP(TOTP::generateSecret(), period: 30);
    $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $cache->method('get')->willReturn(null);
    $cache->expects($this->once())->method('set')->with(
        $this->callback(static fn (mixed $key): bool => is_string($key)),
        100,
        $ttl,
    )->willReturn(true);

    expect($totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        new VerificationWindow($past, $future),
        $cache,
        'factor-window',
    )->matched)->toBeTrue();
})->with([
    'exact only' => [0, 0, 30],
    'past one' => [1, 0, 60],
    'future one' => [0, 1, 60],
    'both one' => [1, 1, 90],
    'maximum total' => [50, 50, 3030],
]);

test('TOTP replay state expires in the actual backend', function () {
    $totp = new TOTP(TOTP::generateSecret(), period: 1);
    $cache = CacheLayerState::memory();
    $code = $totp->generate(100);

    expect($totp->verifyWithWindow($code, 100, cache: $cache, factorId: 'expiring-factor')->matched)
        ->toBeTrue()
        ->and($totp->verifyWithWindow($code, 100, cache: $cache, factorId: 'expiring-factor')->replayDetected)
        ->toBeTrue();

    usleep(1_100_000);

    expect($totp->verifyWithWindow($code, 100, cache: $cache, factorId: 'expiring-factor')->matched)
        ->toBeTrue();
});

test('TOTP replay-state write failure fails closed', function () {
    $totp = new TOTP(TOTP::generateSecret());
    $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $cache->method('get')->willReturn(null);
    $cache->expects($this->once())->method('set')->willReturn(false);

    expect(fn () => $totp->verifyWithWindow(
        $totp->generate(3000),
        3000,
        cache: $cache,
        factorId: 'factor-v1',
    ))->toThrow(RuntimeException::class, 'Unable to store TOTP replay state.');
});
