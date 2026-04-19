<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;

final class InMemoryRecoveryCodeStore implements RecoveryCodeStoreInterface
{
    /**
     * @var array<string, array{codes: array<string, bool>, total:int, lastUsedAt:?DateTimeImmutable}>
     */
    private array $storage = [];

    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): bool
    {
        if (!isset($this->storage[$binding]['codes'][$hashedCode])) {
            return false;
        }

        unset($this->storage[$binding]['codes'][$hashedCode]);
        $this->storage[$binding]['lastUsedAt'] = $usedAt;

        return true;
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

    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundInImplementedInterfaceAfterLastUsed
    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $_issuedAt): void
    {
        $codes = [];
        foreach ($hashedCodes as $hash) {
            $codes[$hash] = true;
        }

        $this->storage[$binding] = [
            'codes' => $codes,
            'total' => count($hashedCodes),
            'lastUsedAt' => null,
        ];
    }
}
