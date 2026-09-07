<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class AotpResponse
{
    public const int VERSION = 1;

    public function __construct(
        public string $challengeId,
        #[\SensitiveParameter]
        public string $signature,
    ) {
        self::assertEncodedLength($challengeId, 16, 'AOTP challenge ID');
        self::assertEncodedLength($signature, SODIUM_CRYPTO_SIGN_BYTES, 'AOTP signature');
    }

    /** @param array<string,mixed> $data */
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

    /** @return array{challengeId:string,signature:string} */
    public function __debugInfo(): array
    {
        return [
            'challengeId' => $this->challengeId,
            'signature' => '[redacted]',
        ];
    }

    private static function assertEncodedLength(string $value, int $bytes, string $name): void
    {
        try {
            $decoded = sodium_base642bin($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new InvalidArgumentException($name . ' must be valid URL-safe Base64 without padding.');
        }
        if (strlen($decoded) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }
    }
}
