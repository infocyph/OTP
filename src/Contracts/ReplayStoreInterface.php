<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

interface ReplayStoreInterface
{
    public function getState(string $namespace, string $binding): int|string|null;

    public function hasConsumed(string $namespace, string $binding, string $token): bool;

    public function markConsumed(string $namespace, string $binding, string $token, ?int $ttl = null): void;

    public function setState(string $namespace, string $binding, int|string|null $value, ?int $ttl = null): void;
}
