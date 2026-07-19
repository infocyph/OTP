<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use InvalidArgumentException;

final class SecretRotationPlanner
{
    /**
     * @param $currentSecret Current normalized Base32 secret.
     * @param $newSecret Replacement Base32 secret.
     * @param $gracePeriodInSeconds Optional overlap duration.
     * @param $now Current timestamp override.
     * @return array Prepared rotation values.
     * @phpstan-return array{nextSecret:string,overlapUntil:?int}
     */
    public static function prepare(
        string $currentSecret,
        string $newSecret,
        ?int $gracePeriodInSeconds,
        ?int $now,
    ): array {
        if ($gracePeriodInSeconds !== null && $gracePeriodInSeconds < 0) {
            throw new InvalidArgumentException('Grace period must be non-negative.');
        }

        $rotationTimestamp = $now ?? time();
        if ($rotationTimestamp < 0) {
            throw new InvalidArgumentException('Rotation timestamp must be non-negative.');
        }
        if ($gracePeriodInSeconds !== null && $rotationTimestamp > PHP_INT_MAX - $gracePeriodInSeconds) {
            throw new InvalidArgumentException('Grace period exceeds the supported timestamp range.');
        }

        $normalizedSecret = SecretUtility::normalizeBase32($newSecret);
        if (hash_equals($currentSecret, $normalizedSecret)) {
            throw new InvalidArgumentException('Replacement secret must differ from the current secret.');
        }

        return [
            'nextSecret' => $normalizedSecret,
            'overlapUntil' => $gracePeriodInSeconds !== null
                ? $rotationTimestamp + $gracePeriodInSeconds
                : null,
        ];
    }
}
