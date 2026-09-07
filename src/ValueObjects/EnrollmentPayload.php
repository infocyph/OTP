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

    /** @return array{secret:string,uri:string,issuer:string,label:string,qrSvg:string|null} */
    public function __debugInfo(): array
    {
        return [
            'secret' => '[redacted]',
            'uri' => '[redacted]',
            'issuer' => $this->issuer,
            'label' => $this->label,
            'qrSvg' => $this->qrSvg === null ? null : '[redacted]',
        ];
    }
}
