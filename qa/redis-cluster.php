<?php

declare(strict_types=1);

namespace Infocyph\OTP\QA;

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Exceptions\CacheBackendException;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\HOTP;
use Infocyph\OTP\MobileOTP;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\TOTP;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use InvalidArgumentException;
use RedisClusterException;
use RuntimeException;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/Support/Concurrency.php';

/** @throws RuntimeException */
function requireClusterResult(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

/**
 * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
 * @throws RuntimeException
 * @throws \LogicException
 */
function clusterCache(): Cache
{
    $seeds = getenv('OTP_CLUSTER_SEEDS');
    if (!is_string($seeds) || preg_match('/\A127\.0\.0\.1:1738[0-5](?:,127\.0\.0\.1:1738[0-5])*\z/D', $seeds) !== 1) {
        throw new RuntimeException('Expected isolated loopback cluster seeds.');
    }

    return Cache::redisCluster(
        'otp-cluster',
        explode(',', $seeds),
        options: new CacheOptions(
            integrityKey: str_repeat('i', 32),
            allowClosures: false,
            allowObjects: false,
            failOpen: false,
        ),
    );
}

/**
 * @throws \Throwable
 */
function admitClusterFactor(string $factor, bool $next, string $owner = 'factor'): bool
{
    $cache = clusterCache();
    $counter = $next ? 43 : 42;
    $timestamp = $next ? 1_800_000_030 : 1_800_000_000;
    $question = $next ? '87654321' : '12345678';
    $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    $window = new VerificationWindow(18, 18);
    $key = str_repeat('k', 32);

    return match ($factor) {
        'hotp' => new HOTP($secret)->verifyWithResult(
            new HOTP($secret)->generate($counter),
            $counter,
            cache: $cache,
            factorId: $owner,
        )->matched,
        'totp' => new TOTP($secret)->verifyWithWindow(
            new TOTP($secret)->generate($timestamp),
            $timestamp,
            $window,
            $cache,
            $owner,
        )->matched,
        'mobile' => new MobileOTP('0123456789abcdef', '1234')->verifyWithWindow(
            new MobileOTP('0123456789abcdef', '1234')->generate($timestamp),
            $timestamp,
            $window,
            cache: $cache,
            factorId: $owner,
        )->matched,
        'ocra-counter' => new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', $key)->verifyWithResult(
            new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', $key)->generate($question, $counter),
            $question,
            $counter,
            cache: $cache,
            factorId: $owner,
        )->matched,
        'ocra-challenge' => new OCRA('OCRA-1:HOTP-SHA256-8:QN08', $key)->verifyWithResult(
            new OCRA('OCRA-1:HOTP-SHA256-8:QN08', $key)->generate($question),
            $question,
            cache: $cache,
            factorId: $owner,
            replayTtl: 600,
        )->matched,
        default => throw new InvalidArgumentException('Unknown cluster factor.'),
    };
}

/** @throws \Throwable */
function clusterGeneric(): GenericOtp
{
    return new GenericOtp(clusterCache(), str_repeat('g', 32), ttlSeconds: 600);
}

/**
 * @param callable(): bool $admit
 * @throws \Throwable
 */
function requireClusterUnavailable(callable $admit): void
{
    try {
        $admit();
    } catch (CacheBackendException|RedisClusterException) {
        return;
    }

    throw new RuntimeException('Unavailable cluster returned a credential outcome instead of a backend failure.');
}

$phase = $argv[1] ?? '';
$factor = $argv[2] ?? '';
if (!in_array($phase, ['seed', 'offline', 'recover'], true)
    || !in_array($factor, ['generic', 'totp', 'hotp', 'mobile', 'ocra-counter', 'ocra-challenge'], true)
) {
    throw new InvalidArgumentException('Expected a cluster phase and factor.');
}

if ($factor === 'generic') {
    if ($phase === 'seed') {
        $proof = clusterGeneric()->generate('factor');
        requireClusterResult(fwrite(STDOUT, $proof) === strlen($proof), 'Unable to write private fixture proof.');
    } else {
        $proof = stream_get_contents(STDIN);
        if (!is_string($proof) || preg_match('/\A[0-9]{6}\z/D', $proof) !== 1) {
            throw new RuntimeException('Invalid private challenge fixture.');
        }
        if ($phase === 'offline') {
            requireClusterUnavailable(static fn(): bool => clusterGeneric()->verify('factor', $proof));
        } else {
            $results = Concurrency::run(static fn(): int => (int) clusterGeneric()->verify('factor', $proof), 4);
            requireClusterResult(array_sum($results) === 1, 'Recovered challenge did not elect exactly one consumer.');
            requireClusterResult(!clusterGeneric()->verify('factor', $proof), 'Recovered challenge replayed.');
            $replacement = clusterGeneric()->generate('other-owner');
            requireClusterResult(clusterGeneric()->verify('other-owner', $replacement), 'Independent owner was not admitted.');
            requireClusterResult(!clusterGeneric()->verify('other-owner', $replacement), 'Independent owner replayed.');
        }
    }
} elseif ($phase === 'seed') {
    requireClusterResult(admitClusterFactor($factor, false), 'Seed proof was rejected.');
    requireClusterResult(!admitClusterFactor($factor, false), 'Seed proof replayed.');
} elseif ($phase === 'offline') {
    requireClusterUnavailable(static fn(): bool => admitClusterFactor($factor, false));
    requireClusterUnavailable(static fn(): bool => admitClusterFactor($factor, true));
} else {
    requireClusterResult(!admitClusterFactor($factor, false), 'Recovery regressed spent proof state.');
    $results = Concurrency::run(static fn(): int => (int) admitClusterFactor($factor, true), 4);
    requireClusterResult(array_sum($results) === 1, 'Recovered factor did not elect exactly one consumer.');
    requireClusterResult(!admitClusterFactor($factor, true), 'Recovered factor replayed.');
    requireClusterResult(admitClusterFactor($factor, true, 'other-owner'), 'Independent owner was not admitted.');
    requireClusterResult(!admitClusterFactor($factor, true, 'other-owner'), 'Independent owner replayed.');
}
