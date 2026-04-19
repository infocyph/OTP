<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use DateTimeImmutable;

final readonly class DeviceEnrollment
{
    public function __construct(
        public string $deviceId,
        public string $label,
        public string $secretReference,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $activatedAt = null,
        public ?DateTimeImmutable $revokedAt = null,
    ) {}

    public function activate(?DateTimeImmutable $activatedAt = null): self
    {
        return new self(
            $this->deviceId,
            $this->label,
            $this->secretReference,
            $this->createdAt,
            $activatedAt ?? new DateTimeImmutable(),
            $this->revokedAt,
        );
    }

    public function isActive(): bool
    {
        return $this->activatedAt !== null && $this->revokedAt === null;
    }

    public function revoke(?DateTimeImmutable $revokedAt = null): self
    {
        return new self(
            $this->deviceId,
            $this->label,
            $this->secretReference,
            $this->createdAt,
            $this->activatedAt,
            $revokedAt ?? new DateTimeImmutable(),
        );
    }
}
