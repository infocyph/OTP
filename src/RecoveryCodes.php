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

    private const int MAX_INPUT_LENGTH = 512;

    private const int MAX_KEY_LENGTH = 1024;

    private const float MIN_ENTROPY_BITS = 40.0;

    public function __construct(
        private RecoveryCodeStoreInterface $store,
        #[\SensitiveParameter]
        private string $key,
    ) {
        if (strlen($key) < 16 || strlen($key) > self::MAX_KEY_LENGTH) {
            throw new InvalidArgumentException('Recovery code HMAC keys must contain between 16 and 1024 bytes.');
        }
    }

    public function consume(string $binding, #[\SensitiveParameter] string $code): RecoveryCodeConsumptionResult
    {
        self::assertBinding($binding);
        if ($code === '' || strlen($code) > self::MAX_INPUT_LENGTH) {
            return $this->invalidResult($binding);
        }

        $normalizedCode = strtoupper(str_replace([' ', '-'], '', trim($code)));
        if (
            strlen($normalizedCode) < 6
            || strlen($normalizedCode) > self::MAX_CODE_LENGTH
            || preg_match('/^[A-Z0-9]+$/', $normalizedCode) !== 1
        ) {
            return $this->invalidResult($binding);
        }

        $state = $this->store->consume(
            $binding,
            $this->digest($binding, $normalizedCode),
            new DateTimeImmutable(),
        );

        return new RecoveryCodeConsumptionResult(
            $state['consumed'],
            $state['remaining'],
            $state['total'],
            $state['lastUsedAt'],
        );
    }

    public function generate(
        string $binding,
        int $count = 10,
        int $length = 12,
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

        $characters = self::characterSet($characterSet);
        if ($length * log(count($characters), 2) < self::MIN_ENTROPY_BITS) {
            throw new InvalidArgumentException('Recovery code configuration must provide at least 40 bits of entropy.');
        }
        if (!self::canGenerateUniqueCodes($count, $length, count($characters))) {
            throw new InvalidArgumentException('Recovery code configuration cannot produce the requested number of unique codes.');
        }

        $plainCodes = [];
        $hashedCodes = [];
        $generatedCodes = [];
        while (count($plainCodes) < $count) {
            $code = self::randomCode($length, $characters);
            if (isset($generatedCodes[$code])) {
                continue;
            }

            $generatedCodes[$code] = true;
            $plainCodes[] = $groupSize > 0 ? trim(chunk_split($code, $groupSize, '-'), '-') : $code;
            $hashedCodes[] = $this->digest($binding, $code);
        }

        $state = $this->store->replace($binding, $hashedCodes, new DateTimeImmutable());

        return new RecoveryCodeGenerationResult(
            $plainCodes,
            $state['total'],
            $state['remaining'],
            $state['lastUsedAt'],
        );
    }

    private static function assertBinding(string $binding): void
    {
        if ($binding === '' || strlen($binding) > 190) {
            throw new InvalidArgumentException('Recovery code bindings must contain between 1 and 190 bytes.');
        }
    }

    private static function canGenerateUniqueCodes(int $count, int $length, int $characterCount): bool
    {
        $requiredCapacity = $count * 2;
        $capacity = 1;
        for ($index = 0; $index < $length; $index++) {
            if ($capacity >= $requiredCapacity || $capacity > intdiv($requiredCapacity - 1, $characterCount)) {
                return true;
            }

            $capacity *= $characterCount;
        }

        return $capacity >= $requiredCapacity;
    }

    /**
     * @param string $characterSet Caller-supplied ASCII alphabet.
     * @return non-empty-list<string>
     */
    private static function characterSet(string $characterSet): array
    {
        $characterSet = strtoupper($characterSet);
        if ($characterSet === '' || preg_match('/^[A-Z0-9]+$/', $characterSet) !== 1) {
            throw new InvalidArgumentException('Recovery code character set must contain only ASCII letters and digits.');
        }

        $unique = [];
        $length = strlen($characterSet);
        for ($index = 0; $index < $length; $index++) {
            $unique[$characterSet[$index]] = true;
        }
        if (count($unique) < 2) {
            throw new InvalidArgumentException('Recovery code character set must contain at least two unique characters.');
        }

        return array_keys($unique);
    }

    /**
     * @param int $length Number of unformatted characters.
     * @param non-empty-list<string> $characters Normalized unique alphabet.
     */
    private static function randomCode(int $length, array $characters): string
    {
        $code = '';
        $characterCount = count($characters);
        $limit = intdiv(256, $characterCount) * $characterCount;
        while (strlen($code) < $length) {
            $bytes = random_bytes(max(16, $length - strlen($code)));
            $byteCount = strlen($bytes);
            for ($index = 0; $index < $byteCount && strlen($code) < $length; $index++) {
                $value = ord($bytes[$index]);
                if ($value < $limit) {
                    $code .= $characters[$value % $characterCount];
                }
            }
        }

        return $code;
    }

    private function digest(string $binding, string $code): string
    {
        return hash_hmac('sha256', "recovery-code\0" . $binding . "\0" . $code, $this->key);
    }

    private function invalidResult(string $binding): RecoveryCodeConsumptionResult
    {
        $state = $this->store->metadata($binding);

        return new RecoveryCodeConsumptionResult(
            false,
            $state['remaining'],
            $state['total'],
            $state['lastUsedAt'],
        );
    }
}
