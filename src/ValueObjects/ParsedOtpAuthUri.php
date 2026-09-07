<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

final readonly class ParsedOtpAuthUri
{
    public function __construct(
        public string $type,
        #[\SensitiveParameter]
        public string $secret,
        public string $label,
        public ?string $issuer,
        public string $algorithm,
        public int $digits,
        public ?int $period,
        public ?int $counter,
        public ?string $ocraSuite,
        /** @var array<string, string> */
        public array $additionalParameters = [],
    ) {}

    /**
     * @return array{
     *     type:string,
     *     secret:string,
     *     label:string,
     *     issuer:?string,
     *     algorithm:string,
     *     digits:int,
     *     period:?int,
     *     counter:?int,
     *     ocraSuite:?string,
     *     additionalParameters:array<string,string>
     * }
     */
    public function __debugInfo(): array
    {
        return [
            'type' => $this->type,
            'secret' => '[redacted]',
            'label' => $this->label,
            'issuer' => $this->issuer,
            'algorithm' => $this->algorithm,
            'digits' => $this->digits,
            'period' => $this->period,
            'counter' => $this->counter,
            'ocraSuite' => $this->ocraSuite,
            'additionalParameters' => $this->additionalParameters,
        ];
    }
}
