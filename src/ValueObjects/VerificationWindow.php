<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class VerificationWindow
{
    public function __construct(
        public int $past = 0,
        public int $future = 0,
    ) {}

    public static function symmetric(int $window): self
    {
        return new self($window, $window);
    }
}
