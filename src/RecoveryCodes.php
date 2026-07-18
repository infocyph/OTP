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
    public function __construct(
        private RecoveryCodeStoreInterface $store,
        private string $hashAlgorithm = 'sha256',
        private ?string $hashKey = null,
    ) {}

    public function consume(string $binding, string $code): RecoveryCodeConsumptionResult
    {
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
        if ($count < 1 || $length < 6 || $groupSize < 0) {
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

    private function canGenerateUniqueCodes(int $count, int $length, int $characterCount): bool
    {
        $capacity = 1;
        for ($i = 0; $i < $length; $i++) {
            if ($capacity >= $count || $capacity > intdiv($count - 1, $characterCount)) {
                return true;
            }

            $capacity *= $characterCount;
        }

        return $capacity >= $count;
    }

    /**
     * @param $characterSet Candidate recovery-code characters.
     * @return array Unique recovery-code characters.
     * @phpstan-return non-empty-list<string>
     */
    private function characterSet(string $characterSet): array
    {
        $characters = [];
        foreach (str_split($characterSet) as $character) {
            $characters[$character] = true;
        }
        if ($characters === []) {
            throw new InvalidArgumentException('Recovery code character set cannot be empty.');
        }

        return array_keys($characters);
    }

    private function hash(string $code): string
    {
        return hash_hmac($this->hashAlgorithm, $code, $this->hashKey ?? 'otp-recovery-codes');
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
