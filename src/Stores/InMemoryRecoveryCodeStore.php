<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;

final class InMemoryRecoveryCodeStore implements RecoveryCodeStoreInterface
{
    /**
     * @var array<string, array{codes: array<string, bool>, total:int, issuedAt:DateTimeImmutable, lastUsedAt:?DateTimeImmutable}>
     */
    private array $storage = [];

    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
    {
        if (!isset($this->storage[$binding]['codes'][$hashedCode])) {
            return ['consumed' => false] + $this->metadata($binding);
        }

        unset($this->storage[$binding]['codes'][$hashedCode]);
        $this->storage[$binding]['lastUsedAt'] = $usedAt;

        return ['consumed' => true] + $this->metadata($binding);
    }

    public function metadata(string $binding): array
    {
        if (!isset($this->storage[$binding])) {
            return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        return [
            'total' => $this->storage[$binding]['total'],
            'remaining' => count($this->storage[$binding]['codes']),
            'lastUsedAt' => $this->storage[$binding]['lastUsedAt'],
        ];
    }

    /**
     * @param string $binding Subject binding identifier.
     * @param list<string> $hashedCodes Unique keyed code digests.
     * @param DateTimeImmutable $issuedAt Batch issuance timestamp.
     */
    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
    {
        $codes = [];
        foreach ($hashedCodes as $hash) {
            if (isset($codes[$hash])) {
                throw new \InvalidArgumentException('Recovery code hashes must be unique.');
            }
            $codes[$hash] = true;
        }

        $this->storage[$binding] = [
            'codes' => $codes,
            'total' => count($codes),
            'issuedAt' => $issuedAt,
            'lastUsedAt' => null,
        ];

        return $this->metadata($binding);
    }
}
