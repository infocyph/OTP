<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class OcraSuite
{
    /**
     * @param array<int, array{format:string, value:int|string}> $optionals
     */
    public function __construct(
        public string $suite,
        public string $algorithm,
        public int $digits,
        public bool $counterEnabled,
        public string $challengeFormat,
        public int $challengeLength,
        public array $optionals = [],
    ) {}
}
