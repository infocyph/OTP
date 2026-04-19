<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class EnrollmentPayload
{
    public function __construct(
        public string $secret,
        public string $uri,
        public string $qrPayload,
        public string $issuer,
        public string $label,
        public ?string $qrSvg = null,
    ) {}
}
