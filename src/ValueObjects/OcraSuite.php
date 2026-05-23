<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class OcraSuite
{
    /**
     * @param $suite Original suite string.
     * @param $algorithm Normalized HMAC algorithm.
     * @param $digits OTP digit length.
     * @param $counterEnabled Whether counter mode is enabled.
     * @param $challengeFormat Challenge format (`n`, `a`, or `h`).
     * @param $challengeLength Challenge length.
     * @param $optionals Parsed optional suite parts.
     * @phpstan-param array<int, array{format:string, value:int|string}> $optionals
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
