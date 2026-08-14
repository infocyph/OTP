<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use DateTimeImmutable;
use Infocyph\OTP\VerificationReason;
use InvalidArgumentException;

final readonly class VerificationResult
{
    private function __construct(
        public bool $matched,
        public VerificationReason $reason,
        public ?int $matchedTimestep = null,
        public ?int $matchedCounter = null,
        public ?int $nextCounter = null,
        public int $driftOffset = 0,
        public bool $replayDetected = false,
        public ?DateTimeImmutable $verifiedAt = null,
    ) {
        if ($matchedTimestep !== null && $matchedCounter !== null) {
            throw new InvalidArgumentException('A verification result cannot contain both timestep and counter state.');
        }
    }

    public static function malformed(): self
    {
        return new self(false, VerificationReason::Malformed);
    }

    public static function mismatch(): self
    {
        return new self(false, VerificationReason::Mismatch);
    }

    public static function replay(
        ?int $matchedTimestep = null,
        ?int $matchedCounter = null,
        int $driftOffset = 0,
    ): self {
        return new self(
            false,
            VerificationReason::Replay,
            $matchedTimestep,
            $matchedCounter,
            null,
            $driftOffset,
            true,
        );
    }

    public static function success(
        VerificationReason $reason = VerificationReason::Matched,
        ?int $matchedTimestep = null,
        ?int $matchedCounter = null,
        ?int $nextCounter = null,
        int $driftOffset = 0,
        ?DateTimeImmutable $verifiedAt = null,
    ): self {
        if (!in_array($reason, [VerificationReason::Matched, VerificationReason::Drifted, VerificationReason::Resynchronized], true)) {
            throw new InvalidArgumentException('Successful verification requires a successful reason.');
        }
        if ($reason === VerificationReason::Matched && $driftOffset !== 0) {
            throw new InvalidArgumentException('An exact match must have a zero drift offset.');
        }
        if ($reason === VerificationReason::Drifted && ($matchedTimestep === null || $matchedCounter !== null || $driftOffset === 0)) {
            throw new InvalidArgumentException('A drifted match requires a timestep, no counter, and a non-zero offset.');
        }
        if ($reason === VerificationReason::Resynchronized && ($matchedCounter === null || $matchedTimestep !== null || $driftOffset <= 0)) {
            throw new InvalidArgumentException('A resynchronized match requires a counter and a positive offset.');
        }
        $expectedNextCounter = $matchedCounter === null || $matchedCounter === PHP_INT_MAX
            ? null
            : $matchedCounter + 1;
        if ($nextCounter !== $expectedNextCounter) {
            throw new InvalidArgumentException('Next counter must be the immediate successor of the matched counter.');
        }

        return new self(
            true,
            $reason,
            $matchedTimestep,
            $matchedCounter,
            $nextCounter,
            $driftOffset,
            false,
            $verifiedAt ?? new DateTimeImmutable(),
        );
    }

    public function isDrifted(): bool
    {
        return $this->matched && $this->driftOffset !== 0;
    }

    public function isExact(): bool
    {
        return $this->matched && $this->driftOffset === 0;
    }
}
