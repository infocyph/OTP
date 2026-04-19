<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;

final readonly class RecoveryCodeGenerationResult
{
    /**
     * @param array<string> $plainCodes
     */
    public function __construct(
        public array $plainCodes,
        public int $totalGenerated,
        public int $remainingCount,
        public ?DateTimeImmutable $lastUsedAt = null,
    ) {}
}
