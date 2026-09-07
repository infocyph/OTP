<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use Infocyph\OTP\Support\Base64Url;
use InvalidArgumentException;

final readonly class AotpResponse
{
    public const int VERSION = 1;

    private const int CHALLENGE_ID_BYTES = 16;

    private const int SIGNATURE_BYTES = 64;

    public function __construct(
        public string $challengeId,
        #[\SensitiveParameter]
        public string $signature,
    ) {
        self::assertEncodedLength($challengeId, self::CHALLENGE_ID_BYTES, 'AOTP challenge ID');
        self::assertEncodedLength($signature, self::SIGNATURE_BYTES, 'AOTP signature');
    }

    /** @return array{challengeId:string,signature:string} */
    public function __debugInfo(): array
    {
        return [
            'challengeId' => $this->challengeId,
            'signature' => '[redacted]',
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        if (
            count($data) !== 3
            || ($data['v'] ?? null) !== self::VERSION
            || !is_string($data['challengeId'] ?? null)
            || !is_string($data['signature'] ?? null)
        ) {
            throw new InvalidArgumentException('Malformed AOTP response payload.');
        }

        return new self($data['challengeId'], $data['signature']);
    }

    /** @return array{v:int,challengeId:string,signature:string} */
    public function toArray(): array
    {
        return [
            'v' => self::VERSION,
            'challengeId' => $this->challengeId,
            'signature' => $this->signature,
        ];
    }

    private static function assertEncodedLength(string $value, int $bytes, string $name): void
    {
        if (strlen(Base64Url::decode($value, $name)) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }
    }
}
