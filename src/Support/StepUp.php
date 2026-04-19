<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use DateTimeImmutable;

final class StepUp
{
    public static function requiresFreshOtp(?DateTimeImmutable $verifiedAt, int $seconds, ?DateTimeImmutable $now = null): bool
    {
        if ($verifiedAt === null) {
            return true;
        }

        return !self::verifiedWithin($verifiedAt, $seconds, $now);
    }

    public static function verifiedWithin(DateTimeImmutable $verifiedAt, int $seconds, ?DateTimeImmutable $now = null): bool
    {
        return ($now ?? new DateTimeImmutable())->getTimestamp() - $verifiedAt->getTimestamp() <= $seconds;
    }
}
