<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;
use Infocyph\OTP\Result\RecoveryCodeConsumptionResult;
use Infocyph\OTP\Result\RecoveryCodeGenerationResult;
use InvalidArgumentException;

final readonly class RecoveryCodes
{
    private const int MAX_CODE_COUNT = 100;

    private const int MAX_CODE_LENGTH = 128;

    private string $hashAlgorithm;

    private ?string $hashKey;

    public function __construct(
        private RecoveryCodeStoreInterface $store,
        string $hashAlgorithm = 'sha256',
        ?string $hashKey = null,
    ) {
        $this->hashAlgorithm = match (strtolower(trim($hashAlgorithm))) {
            'sha256' => 'sha256',
            'sha512' => 'sha512',
            default => throw new InvalidArgumentException('Recovery code hashing requires SHA-256 or SHA-512.'),
        };
        if ($hashKey !== null && strlen($hashKey) < 16) {
            throw new InvalidArgumentException('Recovery code HMAC keys must contain at least 16 bytes.');
        }
        $this->hashKey = $hashKey;
    }

    public function consume(string $binding, string $code): RecoveryCodeConsumptionResult
    {
        self::assertBinding($binding);
        $usedAt = new DateTimeImmutable();
        $normalizedCode = strtoupper(str_replace([' ', '-'], '', trim($code)));
        $consumed = $this->store->consume($binding, $this->hash($normalizedCode), $usedAt);
        $metadata = $this->store->metadata($binding);

        return new RecoveryCodeConsumptionResult(
            $consumed,
            $consumed ? 'consumed' : 'invalid',
            $metadata['remaining'],
            $metadata['total'],
            $metadata['lastUsedAt'],
        );
    }

    public function generate(
        string $binding,
        int $count = 10,
        int $length = 10,
        int $groupSize = 4,
        string $characterSet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
    ): RecoveryCodeGenerationResult {
        self::assertBinding($binding);
        if (
            $count < 1
            || $count > self::MAX_CODE_COUNT
            || $length < 6
            || $length > self::MAX_CODE_LENGTH
            || $groupSize < 0
            || $groupSize > $length
        ) {
            throw new InvalidArgumentException('Invalid recovery code configuration.');
        }

        $characters = $this->characterSet($characterSet);
        if (!$this->canGenerateUniqueCodes($count, $length, count($characters))) {
            throw new InvalidArgumentException('Recovery code configuration cannot produce the requested number of unique codes.');
        }

        $plainCodes = [];
        $hashedCodes = [];
        $generatedCodes = [];
        while (count($plainCodes) < $count) {
            $code = $this->randomCode($length, $characters);
            if (isset($generatedCodes[$code])) {
                continue;
            }

            $generatedCodes[$code] = true;
            $plainCodes[] = $groupSize > 0 ? trim(chunk_split($code, $groupSize, '-'), '-') : $code;
            $hashedCodes[] = $this->hash($code);
        }

        $issuedAt = new DateTimeImmutable();
        $this->store->replace($binding, $hashedCodes, $issuedAt);
        $metadata = $this->store->metadata($binding);

        return new RecoveryCodeGenerationResult($plainCodes, $metadata['total'], $metadata['remaining'], $metadata['lastUsedAt']);
    }

    private static function assertBinding(string $binding): void
    {
        if (trim($binding) === '' || strlen($binding) > 512) {
            throw new InvalidArgumentException('Recovery code binding must contain between 1 and 512 bytes.');
        }
    }

    private function canGenerateUniqueCodes(int $count, int $length, int $characterCount): bool
    {
        if ($characterCount < 2) {
            return false;
        }

        $requiredCapacity = $count * 2;
        $capacity = 1;
        for ($i = 0; $i < $length; $i++) {
            if ($capacity >= $requiredCapacity || $capacity > intdiv($requiredCapacity - 1, $characterCount)) {
                return true;
            }

            $capacity *= $characterCount;
        }

        return $capacity >= $requiredCapacity;
    }

    /**
     * @param $characterSet Candidate recovery-code characters.
     * @return array Unique recovery-code characters.
     * @phpstan-return non-empty-list<string>
     */
    private function characterSet(string $characterSet): array
    {
        $characterSet = strtoupper($characterSet);
        if ($characterSet === '' || preg_match('/^[A-Z0-9]+$/', $characterSet) !== 1) {
            throw new InvalidArgumentException('Recovery code character set must contain only ASCII letters and digits.');
        }

        $characters = [];
        foreach (str_split($characterSet) as $character) {
            $characters[$character] = true;
        }

        return array_keys($characters);
    }

    private function hash(string $code): string
    {
        if ($this->hashKey === null) {
            return hash($this->hashAlgorithm, $code);
        }

        return hash_hmac($this->hashAlgorithm, $code, $this->hashKey);
    }

    /**
     * @param $length Recovery-code length.
     * @param $characterSet Unique recovery-code characters.
     * @phpstan-param non-empty-list<string> $characterSet
     */
    private function randomCode(int $length, array $characterSet): string
    {
        $code = '';
        $characterCount = count($characterSet);
        for ($i = 0; $i < $length; $i++) {
            $code .= $characterSet[random_int(0, $characterCount - 1)];
        }

        return $code;
    }
}
