<?php

declare(strict_types=1);

namespace Infocyph\OTP\Stores;

use Infocyph\OTP\Contracts\OtpStoreInterface;
use InvalidArgumentException;

/** Process-local deterministic store for tests and local development only. */
final class InMemoryOtpStore implements OtpStoreInterface
{
    /** @var array<string, array{digest:string,expiresAt:int,remainingAttempts:int}> */
    private array $challenges = [];

    public function delete(string $storageBinding): bool
    {
        $existed = isset($this->challenges[$storageBinding]);
        unset($this->challenges[$storageBinding]);

        return $existed;
    }

    public function issue(
        string $storageBinding,
        string $digest,
        int $expiresAt,
        int $maxAttempts,
    ): void {
        if ($expiresAt < 0 || $maxAttempts < 1) {
            throw new InvalidArgumentException('Invalid generic OTP state.');
        }

        $this->challenges[$storageBinding] = [
            'digest' => $digest,
            'expiresAt' => $expiresAt,
            'remainingAttempts' => $maxAttempts,
        ];
    }

    public function verifyAndConsume(string $storageBinding, string $candidateDigest, int $now): bool
    {
        $challenge = $this->challenges[$storageBinding] ?? null;
        if ($challenge === null) {
            return false;
        }
        if ($challenge['expiresAt'] <= $now) {
            unset($this->challenges[$storageBinding]);

            return false;
        }
        if (hash_equals($challenge['digest'], $candidateDigest)) {
            unset($this->challenges[$storageBinding]);

            return true;
        }

        $remainingAttempts = $challenge['remainingAttempts'] - 1;
        if ($remainingAttempts === 0) {
            unset($this->challenges[$storageBinding]);
        } else {
            $this->challenges[$storageBinding]['remainingAttempts'] = $remainingAttempts;
        }

        return false;
    }
}
