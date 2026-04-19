<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;

final readonly class StepUpResult
{
    public function __construct(
        public bool $requiresFreshOtp,
        public ?DateTimeImmutable $verifiedAt,
        public ?int $ageInSeconds,
        public int $freshForSeconds,
        public ?DateTimeImmutable $expiresAt,
    ) {}

    public function hasVerification(): bool
    {
        return $this->verifiedAt !== null;
    }

    public function isFresh(): bool
    {
        return !$this->requiresFreshOtp;
    }
}
