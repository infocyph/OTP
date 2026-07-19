<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

interface AtomicReplayStoreInterface extends ReplayStoreInterface
{
    public function advance(string $namespace, string $binding, int $value, ?int $ttl = null): bool;

    public function consumeOnce(string $namespace, string $binding, string $token, ?int $ttl = null): bool;
}
