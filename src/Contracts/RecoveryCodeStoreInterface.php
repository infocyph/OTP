<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

use DateTimeImmutable;

interface RecoveryCodeStoreInterface
{
    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): bool;

    /**
     * @param $binding Subject binding identifier.
     * @return array Recovery-code metadata.
     * @phpstan-return array{total:int,remaining:int,lastUsedAt:?DateTimeImmutable}
     */
    public function metadata(string $binding): array;

    /**
     * @param $binding Subject binding identifier.
     * @param $hashedCodes Hashed recovery codes.
     * @param $issuedAt Issuance timestamp.
     * @phpstan-param list<string> $hashedCodes
     */
    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): void;
}
