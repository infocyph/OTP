<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class EnrollmentPayload
{
    public function __construct(
        #[\SensitiveParameter]
        public string $secret,
        #[\SensitiveParameter]
        public string $uri,
        public string $issuer,
        public string $label,
        #[\SensitiveParameter]
        public ?string $qrSvg = null,
    ) {}
}
