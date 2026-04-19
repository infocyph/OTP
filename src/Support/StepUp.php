<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use DateTimeImmutable;
use Infocyph\OTP\Result\StepUpResult;
use InvalidArgumentException;

final class StepUp
{
    public static function ageInSeconds(DateTimeImmutable $verifiedAt, ?DateTimeImmutable $now = null): int
    {
        return max(0, ($now ?? new DateTimeImmutable())->getTimestamp() - $verifiedAt->getTimestamp());
    }

    public static function assess(?DateTimeImmutable $verifiedAt, int $seconds, ?DateTimeImmutable $now = null): StepUpResult
    {
        self::assertWindow($seconds);
        $now ??= new DateTimeImmutable();

        return new StepUpResult(
            self::requiresFreshOtp($verifiedAt, $seconds, $now),
            $verifiedAt,
            $verifiedAt !== null ? self::ageInSeconds($verifiedAt, $now) : null,
            $seconds,
            $verifiedAt?->modify(sprintf('+%d seconds', $seconds)),
        );
    }

    public static function requiresFreshOtp(?DateTimeImmutable $verifiedAt, int $seconds, ?DateTimeImmutable $now = null): bool
    {
        self::assertWindow($seconds);

        if ($verifiedAt === null) {
            return true;
        }

        return !self::verifiedWithin($verifiedAt, $seconds, $now);
    }

    public static function verifiedWithin(DateTimeImmutable $verifiedAt, int $seconds, ?DateTimeImmutable $now = null): bool
    {
        self::assertWindow($seconds);

        return self::ageInSeconds($verifiedAt, $now) <= $seconds;
    }

    private static function assertWindow(int $seconds): void
    {
        if ($seconds < 0) {
            throw new InvalidArgumentException('Freshness window must be non-negative.');
        }
    }
}
