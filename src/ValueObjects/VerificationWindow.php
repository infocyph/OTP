<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class VerificationWindow
{
    public function __construct(
        public int $past = 0,
        public int $future = 0,
    ) {
        if ($past < 0 || $future < 0) {
            throw new InvalidArgumentException('Verification windows must be non-negative.');
        }
    }

    public static function symmetric(int $window): self
    {
        return new self($window, $window);
    }
}
