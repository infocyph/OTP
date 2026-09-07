<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class PasskeyCeremony
{
    public const string TYPE_AUTHENTICATION = 'authentication';

    public const string TYPE_REGISTRATION = 'registration';

    public function __construct(
        public string $id,
        public string $type,
        #[\SensitiveParameter]
        public string $optionsJson,
        public int $expiresAt,
    ) {
        self::assertId($id);
        if (!in_array($type, [self::TYPE_AUTHENTICATION, self::TYPE_REGISTRATION], true)) {
            throw new InvalidArgumentException('Invalid passkey ceremony type.');
        }
        if ($optionsJson === '' || strlen($optionsJson) > 131072) {
            throw new InvalidArgumentException('Passkey ceremony options must contain between 1 and 131072 bytes.');
        }
        if ($expiresAt < 0) {
            throw new InvalidArgumentException('Passkey ceremony expiration must be non-negative.');
        }
    }

    /** @return array{id:string,type:string,optionsJson:string,expiresAt:int} */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'optionsJson' => '[redacted]',
            'expiresAt' => $this->expiresAt,
        ];
    }

    private static function assertId(string $id): void
    {
        try {
            $decoded = sodium_base642bin($id, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new InvalidArgumentException('Passkey ceremony ID must be valid URL-safe Base64 without padding.');
        }
        if (strlen($decoded) !== 16) {
            throw new InvalidArgumentException('Passkey ceremony ID must encode exactly 16 bytes.');
        }
    }
}
