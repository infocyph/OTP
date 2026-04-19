<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;

final readonly class RecoveryCodeConsumptionResult
{
    public function __construct(
        public bool $consumed,
        public string $reason,
        public int $remainingCount,
        public int $totalGenerated,
        public ?DateTimeImmutable $lastUsedAt,
    ) {}
}
