<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

use DateTimeImmutable;

interface RecoveryCodeStoreInterface
{
    /**
     * Atomically consumes a code and returns the state committed by that mutation.
     *
     * @param string $binding Subject binding identifier.
     * @param string $hashedCode Keyed recovery-code digest.
     * @param DateTimeImmutable $usedAt Successful-use timestamp.
     * @return array{consumed:bool,total:int,remaining:int,lastUsedAt:?DateTimeImmutable}
     */
    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array;

    /**
     * @param string $binding Subject binding identifier.
     * @return array{total:int,remaining:int,lastUsedAt:?DateTimeImmutable} Recovery-code metadata.
     */
    public function metadata(string $binding): array;

    /**
     * @param string $binding Subject binding identifier.
     * @param list<string> $hashedCodes Unique keyed code digests.
     * @param DateTimeImmutable $issuedAt Batch issuance timestamp.
     * @return array{total:int,remaining:int,lastUsedAt:?DateTimeImmutable}
     */
    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array;
}
