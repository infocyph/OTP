<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class OcraSuite
{
    private const string PATTERN = '/^OCRA-1:HOTP-SHA(1|256|512)-(0|[4-9]):(C-)?Q([ANH])(0[4-9]|[1-5]\d|6[0-4])(?:-P(SHA1|SHA256|SHA512))?(?:-S(\d{3}))?(?:-T((?:[1-9]|[1-3]\d|4[0-8])H|(?:[1-9]|[1-5]\d)[SM]))?$/';

    private function __construct(
        public string $suite,
        public string $algorithm,
        public int $digits,
        public bool $counterEnabled,
        public string $challengeFormat,
        public int $challengeLength,
        public ?string $pinAlgorithm,
        public ?int $sessionLength,
        public ?int $timeStepSeconds,
    ) {}

    public static function parse(string $suite): self
    {
        if (preg_match(self::PATTERN, $suite, $matches, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new InvalidArgumentException('Invalid OCRA suite.');
        }

        $sessionLength = $matches[7] !== null ? (int) $matches[7] : null;
        if ($sessionLength !== null && ($sessionLength < 1 || $sessionLength > 512)) {
            throw new InvalidArgumentException('OCRA session length must be between 1 and 512 bytes.');
        }

        return new self(
            $suite,
            'sha' . $matches[1],
            (int) $matches[2],
            $matches[3] !== null,
            strtolower($matches[4]),
            (int) $matches[5],
            $matches[6] !== null ? strtolower($matches[6]) : null,
            $sessionLength,
            self::parseTimeStep($matches[8]),
        );
    }

    public function usesPin(): bool
    {
        return $this->pinAlgorithm !== null;
    }

    public function usesSession(): bool
    {
        return $this->sessionLength !== null;
    }

    public function usesTime(): bool
    {
        return $this->timeStepSeconds !== null;
    }

    private static function parseTimeStep(?string $timeStep): ?int
    {
        if ($timeStep === null) {
            return null;
        }

        $value = (int) substr($timeStep, 0, -1);

        return match (substr($timeStep, -1)) {
            'S' => $value,
            'M' => $value * 60,
            'H' => $value * 3600,
            default => throw new InvalidArgumentException('Invalid OCRA time step.'),
        };
    }
}
