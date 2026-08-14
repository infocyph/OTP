<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

interface OtpStoreInterface
{
    /**
     * Atomically removes the active challenge for this storage binding.
     *
     * @param string $storageBinding Opaque bounded storage key.
     */
    public function delete(string $storageBinding): bool;

    /**
     * Atomically issues or replaces one challenge.
     *
     * @param string $storageBinding Opaque bounded storage key.
     * @param string $digest Keyed candidate digest.
     * @param int $expiresAt Absolute Unix expiration timestamp.
     * @param int $maxAttempts Maximum failed verification attempts.
     */
    public function issue(
        string $storageBinding,
        string $digest,
        int $expiresAt,
        int $maxAttempts,
    ): void;

    /**
     * Atomically verifies and consumes a matching challenge, or decrements one
     * attempt for a mismatch. Expired and exhausted challenges are removed.
     *
     * @param string $storageBinding Opaque bounded storage key.
     * @param string $candidateDigest Keyed submitted-code digest.
     * @param int $now Current Unix timestamp captured by the caller.
     */
    public function verifyAndConsume(
        string $storageBinding,
        string $candidateDigest,
        int $now,
    ): bool;
}
