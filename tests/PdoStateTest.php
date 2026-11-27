<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\Concurrency;
use RuntimeException;

/**
 * @return \Closure(): Cache
 * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
 * @throws \RuntimeException
 */
function pdoStateFactory(string $backend): \Closure
{
    $dsn = getenv('IC_' . $backend . '_DSN');
    $username = getenv('IC_' . $backend . '_USER');
    $password = getenv('IC_' . $backend . '_PASSWORD');
    if (!is_string($dsn) || $dsn === '' || !is_string($username) || !is_string($password)) {
        throw new RuntimeException('The configured native PDO OTP test service is required.');
    }
    $namespace = 'otp-pdo-' . bin2hex(random_bytes(8));
    $options = new CacheOptions(
        integrityKey: random_bytes(32),
        allowClosures: false,
        allowObjects: false,
        failOpen: false,
    );
    return static fn(): Cache => Cache::pdo($namespace, $dsn, $username, $password, options: $options);
}

test('native PDO OTP state is shared and consumed exactly once across connections', function (string $backend): void {
    $factory = pdoStateFactory($backend);
    $cache = $factory();
    $key = random_bytes(32);
    $binding = 'native-pdo-replay';
    $stateKey = hash('sha256', "infocyph:otp:generic:state:v1\0" . $binding);

    try {
        expect(CacheLock::stateAtomic($cache))->not->toBeNull();
        $otp = new GenericOtp($cache, $key);
        $proof = $otp->generate($binding);
        $independent = $factory();
        expect($independent->get($stateKey))->toBeArray();

        $results = Concurrency::run(
            static fn(): int => (int) new GenericOtp($factory(), $key)->verify($binding, $proof),
            4,
        );

        expect(array_sum($results))->toBe(1)
            ->and(new GenericOtp($independent, $key)->verify($binding, $proof))->toBeFalse();

        $replacement = $otp->generate($binding);
        expect(new GenericOtp($independent, $key)->verify($binding, $replacement))->toBeTrue()
            ->and($otp->verify($binding, $replacement))->toBeFalse();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO OCRA claims an initially absent replay record once and isolates replacement factors', function (string $backend): void {
    $factory = pdoStateFactory($backend);
    $cache = $factory();
    $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', '12345678901234567890');
    $challenge = '00000000';
    $proof = $ocra->generate($challenge);
    $stateKey = '05736871982693a8886385eabc65c0c0bb1f63f5c0bcc6d29c68b7ab05d00503';

    try {
        expect($cache->get($stateKey))->toBeNull();
        $results = Concurrency::run(
            static fn(): int => (int) $ocra->verifyWithResult(
                $proof,
                $challenge,
                cache: $factory(),
                factorId: 'factor-v1',
                replayTtl: 300,
            )->matched,
            4,
        );
        $independent = $factory();
        expect(array_sum($results))->toBe(1)
            ->and($independent->get($stateKey))->toBe(1)
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $independent, factorId: 'factor-v1', replayTtl: 300)->matched)->toBeFalse()
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $independent, factorId: 'factor-v2', replayTtl: 300)->matched)->toBeTrue()
            ->and($ocra->verifyWithResult($proof, $challenge, cache: $cache, factorId: 'factor-v2', replayTtl: 300)->matched)->toBeFalse();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);

test('native PDO GenericOtp preserves expiry and attempt ownership across independent writers', function (string $backend): void {
    $factory = pdoStateFactory($backend);
    $cache = $factory();
    $independent = $factory();
    $key = random_bytes(32);
    $binding = 'native-pdo-expiry';
    $stateKey = hash('sha256', "infocyph:otp:generic:state:v1\0" . $binding);
    $otp = new GenericOtp($cache, $key, maxAttempts: 3);
    $verifier = new GenericOtp($independent, $key, maxAttempts: 3);

    try {
        $proof = $otp->generate($binding);
        $wrong = $proof === '000000' ? '000001' : '000000';
        $initial = $independent->get($stateKey);
        if (!is_array($initial) || !is_int($initial['expiresAt'] ?? null)) {
            throw new RuntimeException('Missing native OTP expiry record.');
        }

        expect(Concurrency::run(
            static fn(): int => (int) new GenericOtp($factory(), $key, maxAttempts: 3)->verify($binding, $wrong),
            2,
        ))->toBe([0, 0]);
        expect($independent->get($stateKey))->toBe(array_replace($initial, ['remainingAttempts' => 1]));

        expect($verifier->verify($binding, $wrong))->toBeFalse()
            ->and($otp->verify($binding, $proof))->toBeFalse();

        $proof = $otp->generate($binding);
        $expired = $independent->get($stateKey);
        if (!is_array($expired)) {
            throw new RuntimeException('Missing native OTP replacement record.');
        }

        // Keep the backend row live while its authenticated challenge is expired.
        $expired['expiresAt'] = time() - 1;
        expect($independent->set($stateKey, $expired, 300))->toBeTrue()
            ->and($otp->verify($binding, $proof))->toBeFalse();

        $proof = $otp->generate($binding);
        expect($verifier->delete($binding))->toBeTrue()
            ->and($otp->verify($binding, $proof))->toBeFalse()
            ->and($independent->get($stateKey))->toBeNull();
    } finally {
        $cache->clear();
    }
})->with(['MYSQL', 'MARIADB', 'POSTGRES']);
