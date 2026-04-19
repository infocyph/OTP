<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

use DateTimeImmutable;

interface RecoveryCodeStoreInterface
{
    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): bool;

    /**
     * @return array{total:int,remaining:int,lastUsedAt:?DateTimeImmutable}
     */
    public function metadata(string $binding): array;

    /**
     * @param array<string> $hashedCodes
     */
    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): void;
}
