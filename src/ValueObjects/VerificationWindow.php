<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class VerificationWindow
{
    private const int MAX_TOTAL_WINDOWS = 100;

    public function __construct(
        public int $past = 0,
        public int $future = 0,
    ) {
        if ($past < 0 || $future < 0) {
            throw new InvalidArgumentException('Verification windows must be non-negative.');
        }
        if ($past > self::MAX_TOTAL_WINDOWS - $future) {
            throw new InvalidArgumentException('Verification windows may include at most 100 drift steps.');
        }
    }

    public static function symmetric(int $window): self
    {
        return new self($window, $window);
    }
}
