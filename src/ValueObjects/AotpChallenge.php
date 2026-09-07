<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use Infocyph\OTP\Support\Base64Url;
use InvalidArgumentException;

final readonly class AotpChallenge
{
    public const int VERSION = 1;

    private const int MAX_AUDIENCE_LENGTH = 255;

    private const int MAX_CONTEXT_LENGTH = 4096;

    public function __construct(
        public string $id,
        public string $nonce,
        public string $audience,
        public string $context,
        public int $issuedAt,
        public int $expiresAt,
    ) {
        self::assertEncodedLength($id, 16, 'AOTP challenge ID');
        self::assertAudience($audience);
        self::assertContext($context);
        self::assertEncodedLength($nonce, 32, 'AOTP challenge nonce');
        if ($issuedAt < 0 || $expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('AOTP challenge timestamps are invalid.');
        }
    }

    /** @return array{id:string,nonce:string,audience:string,context:string,issuedAt:int,expiresAt:int} */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'nonce' => '[redacted]',
            'audience' => $this->audience,
            'context' => '[redacted]',
            'issuedAt' => $this->issuedAt,
            'expiresAt' => $this->expiresAt,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        if (
            count($data) !== 7
            || ($data['v'] ?? null) !== self::VERSION
            || !is_string($data['id'] ?? null)
            || !is_string($data['nonce'] ?? null)
            || !is_string($data['audience'] ?? null)
            || !is_string($data['context'] ?? null)
            || !is_int($data['issuedAt'] ?? null)
            || !is_int($data['expiresAt'] ?? null)
        ) {
            throw new InvalidArgumentException('Malformed AOTP challenge payload.');
        }

        return new self(
            $data['id'],
            $data['nonce'],
            $data['audience'],
            $data['context'],
            $data['issuedAt'],
            $data['expiresAt'],
        );
    }

    public function signingPayload(): string
    {
        return "infocyph:aotp:challenge:v1\0"
            . self::packField($this->id)
            . self::packField($this->nonce)
            . self::packField($this->audience)
            . self::packField($this->context)
            . self::packInteger($this->issuedAt)
            . self::packInteger($this->expiresAt);
    }

    /** @return array{v:int,id:string,nonce:string,audience:string,context:string,issuedAt:int,expiresAt:int} */
    public function toArray(): array
    {
        return [
            'v' => self::VERSION,
            'id' => $this->id,
            'nonce' => $this->nonce,
            'audience' => $this->audience,
            'context' => $this->context,
            'issuedAt' => $this->issuedAt,
            'expiresAt' => $this->expiresAt,
        ];
    }

    private static function assertAudience(string $audience): void
    {
        if (
            $audience === ''
            || strlen($audience) > self::MAX_AUDIENCE_LENGTH
            || preg_match('//u', $audience) !== 1
            || preg_match('/[\s\p{Cc}]/u', $audience) === 1
        ) {
            throw new InvalidArgumentException(
                'AOTP audience must be valid UTF-8, contain no whitespace/control characters, and be between 1 and 255 bytes.',
            );
        }
    }

    private static function assertContext(string $context): void
    {
        if (
            $context === ''
            || strlen($context) > self::MAX_CONTEXT_LENGTH
            || preg_match('//u', $context) !== 1
            || preg_match('/\p{Cc}/u', $context) === 1
        ) {
            throw new InvalidArgumentException(
                'AOTP context must be valid UTF-8, contain no control characters, and be between 1 and 4096 bytes.',
            );
        }
    }

    private static function assertEncodedLength(string $value, int $bytes, string $name): void
    {
        if (strlen(Base64Url::decode($value, $name)) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }
    }

    private static function packField(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    private static function packInteger(int $value): string
    {
        return pack('NN', ($value >> 32) & 0xFFFFFFFF, $value & 0xFFFFFFFF);
    }
}
