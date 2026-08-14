<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use Infocyph\OTP\Contracts\ReplayStoreInterface;
use InvalidArgumentException;

/** Process-local deterministic store for tests and local development only. */
final class InMemoryReplayStore implements ReplayStoreInterface
{
    /**
     * @var array<string, array<string, array<string, ?int>>>
     */
    private array $consumed = [];

    /**
     * @var array<string, array<string, array{value:int,expiresAt:?int}>>
     */
    private array $state = [];

    public function advance(string $namespace, string $factorId, int $value, ?int $ttl = null): bool
    {
        self::assertTtl($ttl);
        $now = time();
        $entry = $this->state[$namespace][$factorId] ?? null;
        if ($entry !== null && $entry['expiresAt'] !== null && $entry['expiresAt'] <= $now) {
            unset($this->state[$namespace][$factorId]);
            $entry = null;
        }
        if ($entry !== null && $value <= $entry['value']) {
            return false;
        }

        $this->state[$namespace][$factorId] = [
            'value' => $value,
            'expiresAt' => $ttl !== null ? $now + $ttl : null,
        ];

        return true;
    }

    public function consumeOnce(string $namespace, string $factorId, string $token, ?int $ttl = null): bool
    {
        self::assertTtl($ttl);
        $now = time();
        if (isset($this->consumed[$namespace][$factorId]) && array_key_exists($token, $this->consumed[$namespace][$factorId])) {
            $expiresAt = $this->consumed[$namespace][$factorId][$token];
            if ($expiresAt === null || $expiresAt > $now) {
                return false;
            }
        }

        $this->consumed[$namespace][$factorId][$token] = $ttl !== null ? $now + $ttl : null;

        return true;
    }

    private static function assertTtl(?int $ttl): void
    {
        if ($ttl !== null && $ttl < 1) {
            throw new InvalidArgumentException('Replay state TTL must be greater than zero.');
        }
        if ($ttl !== null && time() > PHP_INT_MAX - $ttl) {
            throw new InvalidArgumentException('Replay state TTL exceeds the supported timestamp range.');
        }
    }
}
