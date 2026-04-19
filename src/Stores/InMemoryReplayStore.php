<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use Infocyph\OTP\Contracts\ReplayStoreInterface;

final class InMemoryReplayStore implements ReplayStoreInterface
{
    /**
     * @var array<string, array<string, array<string, ?int>>>
     */
    private array $consumed = [];

    /**
     * @var array<string, array<string, int|string|null>>
     */
    private array $state = [];

    public function getState(string $namespace, string $binding): int|string|null
    {
        return $this->state[$namespace][$binding] ?? null;
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
        $this->consumed[$namespace][$binding][$token] = $ttl !== null ? time() + $ttl : null;
    }

    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundInImplementedInterfaceAfterLastUsed
    public function setState(string $namespace, string $binding, int|string|null $value, ?int $_ttl = null): void
    {
        $this->state[$namespace][$binding] = $value;
    }
}
