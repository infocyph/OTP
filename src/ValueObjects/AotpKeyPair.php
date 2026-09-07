<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use Infocyph\OTP\Support\Base64Url;
use InvalidArgumentException;

final readonly class AotpKeyPair
{
    private const int PRIVATE_KEY_BYTES = 64;

    private const int PUBLIC_KEY_BYTES = 32;

    public function __construct(
        public string $publicKey,
        #[\SensitiveParameter]
        public string $privateKey,
    ) {
        self::assertEncodedLength($publicKey, self::PUBLIC_KEY_BYTES, 'AOTP public key');
        self::assertEncodedLength($privateKey, self::PRIVATE_KEY_BYTES, 'AOTP private key');
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
        if (strlen(Base64Url::decode($value, $name)) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }
    }
}
