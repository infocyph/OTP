<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class AotpKeyPair
{
    public function __construct(
        public string $publicKey,
        #[\SensitiveParameter]
        public string $privateKey,
    ) {
        self::assertEncodedLength($publicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'AOTP public key');
        self::assertEncodedLength($privateKey, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'AOTP private key');
    }

    /** @return array{publicKey:string,privateKey:string} */
    public function __debugInfo(): array
    {
        return [
            'publicKey' => $this->publicKey,
            'privateKey' => '[redacted]',
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
