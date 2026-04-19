<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class ParsedOtpAuthUri
{
    public function __construct(
        public string $type,
        public string $secret,
        public string $label,
        public ?string $issuer,
        public string $algorithm,
        public int $digits,
        public ?int $period,
        public ?int $counter,
        public ?string $ocraSuite,
    ) {}
}
