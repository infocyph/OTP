<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\OtpStoreInterface;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use PDO;
use Throwable;

/** SQLite integration fixture exercising real cross-process atomic transitions. */
final class SqliteAtomicStore implements OtpStoreInterface, RecoveryCodeStoreInterface, ReplayStoreInterface
{
    private readonly PDO $database;

    public function __construct(string $path)
    {
        $this->database = new PDO('sqlite:' . $path, options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ]);
        $this->database->exec('PRAGMA busy_timeout = 5000');
        $this->database->exec('PRAGMA journal_mode = WAL');
        $this->database->exec(
            'CREATE TABLE IF NOT EXISTS otp_challenges (
                binding TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL
            )',
        );
        $this->database->exec(
            'CREATE TABLE IF NOT EXISTS replay_progress (
                namespace TEXT NOT NULL,
                factor_id TEXT NOT NULL,
                value INTEGER NOT NULL,
                expires_at INTEGER,
                PRIMARY KEY (namespace, factor_id)
            )',
        );
        $this->database->exec(
            'CREATE TABLE IF NOT EXISTS replay_tokens (
                namespace TEXT NOT NULL,
                factor_id TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at INTEGER,
                PRIMARY KEY (namespace, factor_id, token)
            )',
        );
        $this->database->exec(
            'CREATE TABLE IF NOT EXISTS recovery_batches (
                binding TEXT PRIMARY KEY,
                total INTEGER NOT NULL,
                issued_at TEXT NOT NULL,
                last_used_at TEXT
            )',
        );
        $this->database->exec(
            'CREATE TABLE IF NOT EXISTS recovery_codes (
                binding TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                PRIMARY KEY (binding, code_hash)
            )',
        );
    }

    public function advance(string $namespace, string $factorId, int $value, ?int $ttl = null): bool
    {
        return $this->transaction(function () use ($namespace, $factorId, $value, $ttl): bool {
            $now = time();
            $statement = $this->database->prepare(
                'SELECT value, expires_at FROM replay_progress WHERE namespace = ? AND factor_id = ?',
            );
            $statement->execute([$namespace, $factorId]);
            /** @var array{value:int,expires_at:?int}|false $current */
            $current = $statement->fetch(PDO::FETCH_ASSOC);
            if (
                $current !== false
                && ($current['expires_at'] === null || $current['expires_at'] > $now)
                && $value <= $current['value']
            ) {
                return false;
            }

            $statement = $this->database->prepare(
                'INSERT INTO replay_progress (namespace, factor_id, value, expires_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (namespace, factor_id)
                 DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at',
            );
            $statement->execute([$namespace, $factorId, $value, $ttl === null ? null : $now + $ttl]);

            return true;
        });
    }

    public function consumeOnce(string $namespace, string $factorId, string $token, ?int $ttl = null): bool
    {
        return $this->transaction(function () use ($namespace, $factorId, $token, $ttl): bool {
            $now = time();
            $delete = $this->database->prepare(
                'DELETE FROM replay_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?',
            );
            $delete->execute([$now]);
            $insert = $this->database->prepare(
                'INSERT OR IGNORE INTO replay_tokens (namespace, factor_id, token, expires_at) VALUES (?, ?, ?, ?)',
            );
            $insert->execute([$namespace, $factorId, $token, $ttl === null ? null : $now + $ttl]);

            return $insert->rowCount() === 1;
        });
    }

    public function delete(string $storageBinding): bool
    {
        $statement = $this->database->prepare('DELETE FROM otp_challenges WHERE binding = ?');
        $statement->execute([$storageBinding]);

        return $statement->rowCount() === 1;
    }

    public function issue(string $storageBinding, string $digest, int $expiresAt, int $maxAttempts): void
    {
        $this->transaction(function () use ($storageBinding, $digest, $expiresAt, $maxAttempts): void {
            $statement = $this->database->prepare(
                'INSERT INTO otp_challenges (binding, digest, expires_at, attempts)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (binding)
                 DO UPDATE SET digest = excluded.digest, expires_at = excluded.expires_at, attempts = excluded.attempts',
            );
            $statement->execute([$storageBinding, $digest, $expiresAt, $maxAttempts]);
        });
    }

    public function verifyAndConsume(string $storageBinding, string $candidateDigest, int $now): bool
    {
        return $this->transaction(function () use ($storageBinding, $candidateDigest, $now): bool {
            $statement = $this->database->prepare(
                'SELECT digest, expires_at, attempts FROM otp_challenges WHERE binding = ?',
            );
            $statement->execute([$storageBinding]);
            /** @var array{digest:string,expires_at:int,attempts:int}|false $challenge */
            $challenge = $statement->fetch(PDO::FETCH_ASSOC);
            if ($challenge === false) {
                return false;
            }
            if ($challenge['expires_at'] <= $now) {
                $this->delete($storageBinding);

                return false;
            }
            if (hash_equals($challenge['digest'], $candidateDigest)) {
                $this->delete($storageBinding);

                return true;
            }

            if ($challenge['attempts'] <= 1) {
                $this->delete($storageBinding);
            } else {
                $update = $this->database->prepare(
                    'UPDATE otp_challenges SET attempts = attempts - 1 WHERE binding = ?',
                );
                $update->execute([$storageBinding]);
            }

            return false;
        });
    }

    public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
    {
        return $this->transaction(function () use ($binding, $hashedCode, $usedAt): array {
            $statement = $this->database->prepare(
                'DELETE FROM recovery_codes WHERE binding = ? AND code_hash = ?',
            );
            $statement->execute([$binding, $hashedCode]);
            $consumed = $statement->rowCount() === 1;
            if ($consumed) {
                $update = $this->database->prepare(
                    'UPDATE recovery_batches SET last_used_at = ? WHERE binding = ?',
                );
                $update->execute([$usedAt->format(DATE_ATOM), $binding]);
            }

            return ['consumed' => $consumed] + $this->metadata($binding);
        });
    }

    public function metadata(string $binding): array
    {
        $statement = $this->database->prepare(
            'SELECT total, last_used_at FROM recovery_batches WHERE binding = ?',
        );
        $statement->execute([$binding]);
        /** @var array{total:int,last_used_at:?string}|false $batch */
        $batch = $statement->fetch(PDO::FETCH_ASSOC);
        if ($batch === false) {
            return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        $count = $this->database->prepare('SELECT COUNT(*) FROM recovery_codes WHERE binding = ?');
        $count->execute([$binding]);

        return [
            'total' => $batch['total'],
            'remaining' => (int) $count->fetchColumn(),
            'lastUsedAt' => $batch['last_used_at'] === null ? null : new DateTimeImmutable($batch['last_used_at']),
        ];
    }

    public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
    {
        return $this->transaction(function () use ($binding, $hashedCodes, $issuedAt): array {
            $delete = $this->database->prepare('DELETE FROM recovery_codes WHERE binding = ?');
            $delete->execute([$binding]);
            $batch = $this->database->prepare(
                'INSERT INTO recovery_batches (binding, total, issued_at, last_used_at)
                 VALUES (?, ?, ?, NULL)
                 ON CONFLICT (binding)
                 DO UPDATE SET total = excluded.total, issued_at = excluded.issued_at, last_used_at = NULL',
            );
            $batch->execute([$binding, count($hashedCodes), $issuedAt->format(DATE_ATOM)]);
            $insert = $this->database->prepare(
                'INSERT INTO recovery_codes (binding, code_hash) VALUES (?, ?)',
            );
            foreach ($hashedCodes as $hashedCode) {
                $insert->execute([$binding, $hashedCode]);
            }

            return $this->metadata($binding);
        });
    }

    /** @template T */
    /** @param callable(): T $operation */
    /** @return T */
    private function transaction(callable $operation): mixed
    {
        $this->database->exec('BEGIN IMMEDIATE');
        try {
            $result = $operation();
            $this->database->exec('COMMIT');

            return $result;
        } catch (Throwable $throwable) {
            try {
                $this->database->exec('ROLLBACK');
            } catch (Throwable) {
                // Preserve the original operation failure.
            }

            throw $throwable;
        }
    }
}
