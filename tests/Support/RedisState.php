<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Throwable;

final class RedisState
{
    public static function available(): bool
    {
        if (!class_exists(\Redis::class)) {
            return false;
        }

        try {
            self::client()->ping();

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    public static function cache(string $namespace): AuthenticationStateCacheInterface
    {
        $cache = Cache::redis(
            $namespace,
            sprintf('redis://%s:%d', self::host(), self::port()),
            self::client(),
            new CacheOptions(
                integrityKey: str_repeat('i', 32),
                allowClosures: false,
                allowObjects: false,
                failOpen: false,
            ),
        );

        return $cache;
    }

    private static function client(): \Redis
    {
        $client = new \Redis();
        $client->connect(self::host(), self::port(), 1.0);
        $password = getenv('IC_REDIS_PASSWORD') ?: getenv('CACHELAYER_REDIS_PASSWORD');
        if (is_string($password) && $password !== '') {
            $client->auth($password);
        }

        return $client;
    }

    private static function host(): string
    {
        $host = getenv('IC_REDIS_HOST') ?: getenv('CACHELAYER_REDIS_HOST');

        return is_string($host) && $host !== '' ? $host : '127.0.0.1';
    }

    private static function port(): int
    {
        return (int) (getenv('IC_REDIS_PORT') ?: getenv('CACHELAYER_REDIS_PORT') ?: 6379);
    }
}
