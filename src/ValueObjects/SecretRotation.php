<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use DateTimeImmutable;

final readonly class SecretRotation
{
    public function __construct(
        public string $currentSecret,
        public string $nextSecret,
        public ?DateTimeImmutable $overlapUntil = null,
        public ?EnrollmentPayload $nextEnrollment = null,
    ) {}

    public function hasGracePeriod(): bool
    {
        return $this->overlapUntil !== null;
    }

    public function isDualSecretActive(?DateTimeImmutable $at = null): bool
    {
        if ($this->overlapUntil === null) {
            return false;
        }

        return ($at ?? new DateTimeImmutable()) <= $this->overlapUntil;
    }

    public function requiresImmediateCutover(): bool
    {
        return $this->overlapUntil === null;
    }
}
