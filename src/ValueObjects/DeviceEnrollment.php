<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use DateTimeImmutable;
use InvalidArgumentException;

final readonly class DeviceEnrollment
{
    public function __construct(
        public string $deviceId,
        public string $label,
        public string $secretReference,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $activatedAt = null,
        public ?DateTimeImmutable $revokedAt = null,
    ) {
        self::assertNonEmpty('deviceId', $deviceId);
        self::assertNonEmpty('label', $label);
        self::assertNonEmpty('secretReference', $secretReference);
        if ($activatedAt !== null && $activatedAt < $createdAt) {
            throw new InvalidArgumentException('Enrollment activation cannot precede creation.');
        }
        if ($revokedAt !== null && $revokedAt < $createdAt) {
            throw new InvalidArgumentException('Enrollment revocation cannot precede creation.');
        }
        if ($activatedAt !== null && $revokedAt !== null && $revokedAt < $activatedAt) {
            throw new InvalidArgumentException('Enrollment revocation cannot precede activation.');
        }
    }

    public static function create(
        string $deviceId,
        string $label,
        string $secretReference,
        ?DateTimeImmutable $createdAt = null,
    ): self {
        return new self($deviceId, $label, $secretReference, $createdAt ?? new DateTimeImmutable());
    }

    public function activate(?DateTimeImmutable $activatedAt = null): self
    {
        if ($this->isRevoked()) {
            throw new InvalidArgumentException('Revoked enrollments cannot be activated.');
        }
        if ($this->isActive()) {
            throw new InvalidArgumentException('Active enrollments cannot be activated again.');
        }

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

    public function isPendingActivation(): bool
    {
        return $this->activatedAt === null && $this->revokedAt === null;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    public function rename(string $label): self
    {
        self::assertNonEmpty('label', $label);

        return new self(
            $this->deviceId,
            $label,
            $this->secretReference,
            $this->createdAt,
            $this->activatedAt,
            $this->revokedAt,
        );
    }

    public function revoke(?DateTimeImmutable $revokedAt = null): self
    {
        if ($this->isRevoked()) {
            throw new InvalidArgumentException('Revoked enrollments cannot be revoked again.');
        }

        return new self(
            $this->deviceId,
            $this->label,
            $this->secretReference,
            $this->createdAt,
            $this->activatedAt,
            $revokedAt ?? new DateTimeImmutable(),
        );
    }

    public function withSecretReference(string $secretReference): self
    {
        self::assertNonEmpty('secretReference', $secretReference);

        return new self(
            $this->deviceId,
            $this->label,
            $secretReference,
            $this->createdAt,
            $this->activatedAt,
            $this->revokedAt,
        );
    }

    private static function assertNonEmpty(string $field, string $value): void
    {
        if (trim($value) === '') {
            throw new InvalidArgumentException(sprintf('%s cannot be empty.', $field));
        }
    }
}
