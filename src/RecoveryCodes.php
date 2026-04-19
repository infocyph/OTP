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

        $plainCodes = [];
        $hashedCodes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = $this->randomCode($length, $characterSet);
            $plainCodes[] = $groupSize > 0 ? trim(chunk_split($code, $groupSize, '-'), '-') : $code;
            $hashedCodes[] = $this->hash($code);
        }

        $issuedAt = new DateTimeImmutable();
        $this->store->replace($binding, $hashedCodes, $issuedAt);
        $metadata = $this->store->metadata($binding);

        return new RecoveryCodeGenerationResult($plainCodes, $metadata['total'], $metadata['remaining'], $metadata['lastUsedAt']);
    }

    private function hash(string $code): string
    {
        return hash_hmac($this->hashAlgorithm, $code, $this->hashKey ?? 'otp-recovery-codes');
    }

    private function randomCode(int $length, string $characterSet): string
    {
        $characters = array_values(array_unique(str_split($characterSet)));
        if ($characters === []) {
            throw new InvalidArgumentException('Recovery code character set cannot be empty.');
        }

        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= $characters[random_int(0, count($characters) - 1)];
        }

        return $code;
    }
}
