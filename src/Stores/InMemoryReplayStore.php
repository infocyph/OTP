<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use Infocyph\OTP\Contracts\AtomicReplayStoreInterface;
use InvalidArgumentException;

final class InMemoryReplayStore implements AtomicReplayStoreInterface
{
    /**
     * @var array<string, array<string, array<string, ?int>>>
     */
    private array $consumed = [];

    /**
     * @var array<string, array<string, array{value:int|string|null,expiresAt:?int}>>
     */
    private array $state = [];

    public function advance(string $namespace, string $binding, int $value, ?int $ttl = null): bool
    {
        self::assertTtl($ttl);
        $current = $this->getState($namespace, $binding);
        if (is_int($current) && $value <= $current) {
            return false;
        }

        $this->setState($namespace, $binding, $value, $ttl);

        return true;
    }

    public function consumeOnce(string $namespace, string $binding, string $token, ?int $ttl = null): bool
    {
        self::assertTtl($ttl);
        if ($this->hasConsumed($namespace, $binding, $token)) {
            return false;
        }

        $this->markConsumed($namespace, $binding, $token, $ttl);

        return true;
    }

    public function getState(string $namespace, string $binding): int|string|null
    {
        if (!isset($this->state[$namespace][$binding])) {
            return null;
        }

        $entry = $this->state[$namespace][$binding];
        if ($entry['expiresAt'] !== null && $entry['expiresAt'] <= time()) {
            unset($this->state[$namespace][$binding]);

            return null;
        }

        return $entry['value'];
    }

    public function hasConsumed(string $namespace, string $binding, string $token): bool
    {
        if (!isset($this->consumed[$namespace][$binding]) || !array_key_exists($token, $this->consumed[$namespace][$binding])) {
            return false;
        }

        $expiresAt = $this->consumed[$namespace][$binding][$token];
        if ($expiresAt !== null && $expiresAt <= time()) {
            unset($this->consumed[$namespace][$binding][$token]);

            return false;
        }

        return true;
    }

    public function markConsumed(string $namespace, string $binding, string $token, ?int $ttl = null): void
    {
        self::assertTtl($ttl);
        $this->consumed[$namespace][$binding][$token] = $ttl !== null ? time() + $ttl : null;
    }

    public function setState(string $namespace, string $binding, int|string|null $value, ?int $ttl = null): void
    {
        self::assertTtl($ttl);
        $this->state[$namespace][$binding] = [
            'value' => $value,
            'expiresAt' => $ttl !== null ? time() + $ttl : null,
        ];
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
