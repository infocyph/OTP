<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;

final readonly class VerificationResult
{
    public function __construct(
        public bool $matched,
        public string $reason = 'mismatch',
        public ?int $matchedTimestep = null,
        public ?int $matchedCounter = null,
        public int $driftOffset = 0,
        public bool $replayDetected = false,
        public ?DateTimeImmutable $verifiedAt = null,
    ) {}

    public function isDrifted(): bool
    {
        return $this->matched && $this->driftOffset !== 0;
    }

    public function isExact(): bool
    {
        return $this->matched && $this->driftOffset === 0;
    }
}
