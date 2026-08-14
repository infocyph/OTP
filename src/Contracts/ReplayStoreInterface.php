<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

interface ReplayStoreInterface
{
    /**
     * Atomically stores the value only when it is greater than the current value.
     *
     * @param string $namespace Package-owned replay-state namespace.
     * @param string $factorId Factor and secret-generation identifier.
     * @param int $value Monotonically increasing moving factor.
     * @param ?int $ttl Optional state lifetime in seconds.
     */
    public function advance(string $namespace, string $factorId, int $value, ?int $ttl = null): bool;

    /**
     * Atomically consumes a token exactly once.
     *
     * @param string $namespace Package-owned replay-state namespace.
     * @param string $factorId Factor and secret-generation identifier.
     * @param string $token Fixed-size replay token.
     * @param ?int $ttl Optional token-retention lifetime in seconds.
     */
    public function consumeOnce(string $namespace, string $factorId, string $token, ?int $ttl = null): bool;
}
