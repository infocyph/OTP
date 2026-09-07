<?php

declare(strict_types=1);

namespace Infocyph\OTP\ValueObjects;

use InvalidArgumentException;

final readonly class GridChallenge
{
    public const int VERSION = 1;
    public const string SECRET_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    public const string RESPONSE_ALPHABET = '0123456789';

    /** @var array<string,string> */
    public array $grid;

    /** @var list<int> */
    public array $positions;

    /**
     * @param array<string,string> $grid
     * @param list<int> $positions One-based secret positions in response order.
     */
    public function __construct(
        public string $id,
        array $grid,
        array $positions,
        public int $secretLength,
        public int $issuedAt,
        public int $expiresAt,
    ) {
        self::assertEncodedLength($id, 16, 'GridOTP challenge ID');
        if ($secretLength < 8 || $secretLength > 32) {
            throw new InvalidArgumentException('GridOTP secret length must be between 8 and 32 symbols.');
        }
        if ($issuedAt < 0 || $expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('GridOTP challenge timestamps are invalid.');
        }
        if (count($positions) < 6 || count($positions) > 10 || count($positions) > $secretLength) {
            throw new InvalidArgumentException('GridOTP challenges must request between 6 and 10 secret positions.');
        }
        $seen = [];
        foreach ($positions as $position) {
            if (!is_int($position) || $position < 1 || $position > $secretLength || isset($seen[$position])) {
                throw new InvalidArgumentException('GridOTP challenge positions must be distinct and within the secret length.');
            }
            $seen[$position] = true;
        }

        $canonical = [];
        $counts = array_fill_keys(str_split(self::RESPONSE_ALPHABET), 0);
        foreach (str_split(self::SECRET_ALPHABET) as $symbol) {
            $value = $grid[$symbol] ?? null;
            if (!is_string($value) || strlen($value) !== 1 || !array_key_exists($value, $counts)) {
                throw new InvalidArgumentException('GridOTP challenge contains an invalid grid mapping.');
            }
            $canonical[$symbol] = $value;
            $counts[$value]++;
        }
        if (count($grid) !== strlen(self::SECRET_ALPHABET)) {
            throw new InvalidArgumentException('GridOTP challenge grid must contain the complete secret alphabet exactly once.');
        }
        foreach ($counts as $count) {
            if ($count < 3 || $count > 4) {
                throw new InvalidArgumentException('GridOTP response labels must be balanced across the grid.');
            }
        }

        $this->grid = $canonical;
        $this->positions = array_values($positions);
    }

    /** @param array<string,mixed> $data */
    public static function fromArray(array $data): self
    {
        if (
            count($data) !== 7
            || ($data['v'] ?? null) !== self::VERSION
            || !is_string($data['id'] ?? null)
            || !is_array($data['grid'] ?? null)
            || !is_array($data['positions'] ?? null)
            || !is_int($data['secretLength'] ?? null)
            || !is_int($data['issuedAt'] ?? null)
            || !is_int($data['expiresAt'] ?? null)
        ) {
            throw new InvalidArgumentException('Malformed GridOTP challenge payload.');
        }

        /** @var array<string,string> $grid */
        $grid = $data['grid'];
        /** @var list<int> $positions */
        $positions = array_values($data['positions']);

        return new self(
            $data['id'],
            $grid,
            $positions,
            $data['secretLength'],
            $data['issuedAt'],
            $data['expiresAt'],
        );
    }

    public function canonicalPayload(): string
    {
        $mapping = '';
        foreach ($this->grid as $symbol => $value) {
            $mapping .= $symbol . $value;
        }

        return "infocyph:gridotp:challenge:v1\0"
            . self::packField($this->id)
            . self::packField($mapping)
            . self::packField(implode(',', $this->positions))
            . pack('N', $this->secretLength)
            . self::packInteger($this->issuedAt)
            . self::packInteger($this->expiresAt);
    }

    /** @return array{v:int,id:string,grid:array<string,string>,positions:list<int>,secretLength:int,issuedAt:int,expiresAt:int} */
    public function toArray(): array
    {
        return [
            'v' => self::VERSION,
            'id' => $this->id,
            'grid' => $this->grid,
            'positions' => $this->positions,
            'secretLength' => $this->secretLength,
            'issuedAt' => $this->issuedAt,
            'expiresAt' => $this->expiresAt,
        ];
    }

    /** @return array{id:string,grid:string,positions:string,secretLength:int,issuedAt:int,expiresAt:int} */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'grid' => '[redacted]',
            'positions' => '[redacted]',
            'secretLength' => $this->secretLength,
            'issuedAt' => $this->issuedAt,
            'expiresAt' => $this->expiresAt,
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

    private static function packField(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    private static function packInteger(int $value): string
    {
        return pack('NN', ($value >> 32) & 0xFFFFFFFF, $value & 0xFFFFFFFF);
    }
}
