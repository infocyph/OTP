<?php

namespace Infocyph\OTP\Tests\Support;

use DateInterval;
use DateTimeImmutable;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

final class InMemoryCacheItemPool implements CacheItemPoolInterface
{
    /**
     * @var array<string, array{value: mixed, expiresAt: ?int}>
     */
    private array $items = [];

    public function getItem(string $key): CacheItemInterface
    {
        $this->pruneExpired($key);

        if (! array_key_exists($key, $this->items)) {
            return new InMemoryCacheItem($key);
        }

        return new InMemoryCacheItem(
            $key,
            $this->items[$key]['value'],
            true,
            $this->items[$key]['expiresAt'],
        );
    }

    public function getItems(array $keys = []): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->getItem($key);
        }
    }

    public function hasItem(string $key): bool
    {
        $this->pruneExpired($key);

        return array_key_exists($key, $this->items);
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function deleteItem(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            unset($this->items[$key]);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        if (! $item instanceof InMemoryCacheItem) {
            return false;
        }

        $expiresAt = $item->getExpirationTimestamp();
        if ($expiresAt !== null && $expiresAt <= time()) {
            unset($this->items[$item->getKey()]);

            return true;
        }

        $this->items[$item->getKey()] = [
            'value' => $item->get(),
            'expiresAt' => $expiresAt,
        ];

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->save($item);
    }

    public function commit(): bool
    {
        return true;
    }

    public function expire(string $key): void
    {
        if (! array_key_exists($key, $this->items)) {
            return;
        }

        $this->items[$key]['expiresAt'] = time() - 1;
    }

    private function pruneExpired(string $key): void
    {
        if (! array_key_exists($key, $this->items)) {
            return;
        }

        $expiresAt = $this->items[$key]['expiresAt'];
        if ($expiresAt !== null && $expiresAt <= time()) {
            unset($this->items[$key]);
        }
    }
}

final class InMemoryCacheItem implements CacheItemInterface
{
    private mixed $value;

    private bool $isHit;

    private ?int $expiresAt;

    public function __construct(
        private readonly string $key,
        mixed $value = null,
        bool $isHit = false,
        ?int $expiresAt = null,
    ) {
        $this->value = $value;
        $this->isHit = $isHit;
        $this->expiresAt = $expiresAt;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->value;
    }

    public function isHit(): bool
    {
        return $this->isHit && ($this->expiresAt === null || $this->expiresAt > time());
    }

    public function set(mixed $value): static
    {
        $this->value = $value;
        $this->isHit = true;

        return $this;
    }

    public function expiresAt(?\DateTimeInterface $expiration): static
    {
        $this->expiresAt = $expiration?->getTimestamp();

        return $this;
    }

    public function expiresAfter(int|DateInterval|null $time): static
    {
        if ($time === null) {
            $this->expiresAt = null;

            return $this;
        }

        if ($time instanceof DateInterval) {
            $time = (new DateTimeImmutable())->add($time)->getTimestamp() - time();
        }

        $this->expiresAt = time() + $time;

        return $this;
    }

    public function getExpirationTimestamp(): ?int
    {
        return $this->expiresAt;
    }
}
