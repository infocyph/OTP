<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;

final readonly class RecoveryCodeGenerationResult
{
    /**
     * @param $plainCodes Generated plain recovery codes.
     * @param $totalGenerated Total issued code count.
     * @param $remainingCount Remaining unconsumed code count.
     * @param $lastUsedAt Last code consumption timestamp.
     * @phpstan-param list<string> $plainCodes
     */
    public function __construct(
        public array $plainCodes,
        public int $totalGenerated,
        public int $remainingCount,
        public ?DateTimeImmutable $lastUsedAt = null,
    ) {}
}
