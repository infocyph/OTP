<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;
use PDO;
use Throwable;

/** SQLite integration fixture exercising real cross-process atomic transitions. */
final class SqliteAtomicStore implements RecoveryCodeStoreInterface
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
