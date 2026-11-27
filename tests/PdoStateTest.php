<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\Concurrency;
use RuntimeException;

test('native PDO OTP state is shared and consumed exactly once across connections', function (string $backend): void {
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
    $factory = static fn(): Cache => Cache::pdo($namespace, $dsn, $username, $password, options: $options);
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
            static fn(int $worker): int => (int) new GenericOtp($factory(), $key)->verify($binding, $proof),
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
