<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use DateTimeImmutable;
use InvalidArgumentException;

final readonly class SecretRotation
{
    public function __construct(
        public string $currentSecret,
        public string $nextSecret,
        public ?DateTimeImmutable $overlapUntil = null,
        public ?EnrollmentPayload $nextEnrollment = null,
    ) {
        if (trim($currentSecret) === '' || trim($nextSecret) === '') {
            throw new InvalidArgumentException('Rotation secrets cannot be empty.');
        }
        if (hash_equals($currentSecret, $nextSecret)) {
            throw new InvalidArgumentException('Replacement secret must differ from the current secret.');
        }
    }

    public function hasGracePeriod(): bool
    {
        return $this->overlapUntil !== null;
    }

    public function isDualSecretActive(?DateTimeImmutable $at = null): bool
    {
        if ($this->overlapUntil === null) {
            return false;
        }

        return ($at ?? new DateTimeImmutable()) < $this->overlapUntil;
    }

    public function requiresImmediateCutover(): bool
    {
        return $this->overlapUntil === null;
    }
}
