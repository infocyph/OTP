<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use DateTimeImmutable;
use Infocyph\OTP\Support\SecretUtility;
use InvalidArgumentException;

final readonly class SecretRotation
{
    public function __construct(
        #[\SensitiveParameter]
        public string $currentSecret,
        #[\SensitiveParameter]
        public string $nextSecret,
        public ?DateTimeImmutable $overlapUntil = null,
        public ?EnrollmentPayload $nextEnrollment = null,
    ) {
        $current = SecretUtility::normalizeBase32($currentSecret);
        $next = SecretUtility::normalizeBase32($nextSecret);
        SecretUtility::requireStrongBase32($current);
        SecretUtility::requireStrongBase32($next);
        if (!hash_equals($currentSecret, $current) || !hash_equals($nextSecret, $next)) {
            throw new InvalidArgumentException('Rotation secrets must use normalized canonical Base32.');
        }
        if (hash_equals($current, $next)) {
            throw new InvalidArgumentException('Replacement secret must differ from the current secret.');
        }
        if ($nextEnrollment !== null && !hash_equals($next, $nextEnrollment->secret)) {
            throw new InvalidArgumentException('Next enrollment must contain the replacement secret.');
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
