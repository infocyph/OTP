Custom Persistent Stores
========================

Overview
--------

The package ships with in-memory examples for replay tracking and recovery-code tracking, but production systems usually need durable storage.

This guide shows how to build your own database-backed classes using the package contracts.

Contracts
---------

The relevant contracts are:

- ``Infocyph\OTP\Contracts\RecoveryCodeStoreInterface``
- ``Infocyph\OTP\Contracts\ReplayStoreInterface``
- ``Infocyph\OTP\Contracts\SecretStoreInterface``

Secret storage guidance
-----------------------

For TOTP, HOTP, and many OCRA deployments, the application must be able to read the secret again later to generate or verify future OTPs.

That means:

- hashing alone is not enough for OTP secrets
- encryption at rest is usually the correct default
- the stored record should have a stable reference or key id
- rotation should create a new secret record rather than overwrite history blindly

Recovery code tracking in a database
------------------------------------

Recommended schema
~~~~~~~~~~~~~~~~~~

One practical design is a batch table plus per-code rows.

Example schema:

.. code-block:: sql

   CREATE TABLE recovery_code_batches (
       id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
       binding VARCHAR(190) NOT NULL,
       created_at TIMESTAMP NOT NULL,
       revoked_at TIMESTAMP NULL
   );

   CREATE INDEX idx_recovery_code_batches_binding
       ON recovery_code_batches (binding);

   CREATE TABLE recovery_codes (
       id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
       batch_id BIGINT NOT NULL,
       code_hash VARCHAR(255) NOT NULL,
       used_at TIMESTAMP NULL,
       CONSTRAINT fk_recovery_codes_batch
           FOREIGN KEY (batch_id) REFERENCES recovery_code_batches (id)
   );

   CREATE INDEX idx_recovery_codes_batch
       ON recovery_codes (batch_id);

   CREATE INDEX idx_recovery_codes_hash
       ON recovery_codes (code_hash);

How tracking works
~~~~~~~~~~~~~~~~~~

If a user has 6 recovery codes:

- ``total`` is the number originally issued in the active batch
- ``remaining`` is the number of rows where ``used_at IS NULL``
- ``used`` is ``total - remaining``

That means your system can answer, day to day:

- how many codes were issued
- how many are still unused
- when a code was last used

Example PDO store
~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php

   declare(strict_types=1);

   use DateTimeImmutable;
   use DateTimeZone;
   use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;
   use PDO;
   use RuntimeException;

   final readonly class PdoRecoveryCodeStore implements RecoveryCodeStoreInterface
   {
       public function __construct(
           private PDO $pdo,
       ) {}

       public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): void
       {
           $this->pdo->beginTransaction();

           try {
               $statement = $this->pdo->prepare(
                   'UPDATE recovery_code_batches
                    SET revoked_at = :revoked_at
                    WHERE binding = :binding AND revoked_at IS NULL'
               );

               $statement->execute([
                   'binding' => $binding,
                   'revoked_at' => $issuedAt->format('Y-m-d H:i:s'),
               ]);

               $statement = $this->pdo->prepare(
                   'INSERT INTO recovery_code_batches (binding, created_at, revoked_at)
                    VALUES (:binding, :created_at, NULL)'
               );

               $statement->execute([
                   'binding' => $binding,
                   'created_at' => $issuedAt->format('Y-m-d H:i:s'),
               ]);

               $batchId = (int) $this->pdo->lastInsertId();
               if ($batchId < 1) {
                   throw new RuntimeException('Unable to create recovery code batch.');
               }

               $insert = $this->pdo->prepare(
                   'INSERT INTO recovery_codes (batch_id, code_hash, used_at)
                    VALUES (:batch_id, :code_hash, NULL)'
               );

               foreach ($hashedCodes as $hash) {
                   $insert->execute([
                       'batch_id' => $batchId,
                       'code_hash' => $hash,
                   ]);
               }

               $this->pdo->commit();
           } catch (\Throwable $exception) {
               $this->pdo->rollBack();
               throw $exception;
           }
       }

       public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): bool
       {
           $statement = $this->pdo->prepare(
               'UPDATE recovery_codes
                SET used_at = :used_at
                WHERE id = (
                    SELECT rc.id
                    FROM recovery_codes rc
                    INNER JOIN recovery_code_batches rcb ON rcb.id = rc.batch_id
                    WHERE rcb.binding = :binding
                      AND rcb.revoked_at IS NULL
                      AND rc.code_hash = :code_hash
                      AND rc.used_at IS NULL
                    FETCH FIRST 1 ROWS ONLY
                )'
           );

           $statement->execute([
               'binding' => $binding,
               'code_hash' => $hashedCode,
               'used_at' => $usedAt->format('Y-m-d H:i:s'),
           ]);

           return $statement->rowCount() === 1;
       }

       public function metadata(string $binding): array
       {
           $statement = $this->pdo->prepare(
               'SELECT
                    COUNT(rc.id) AS total,
                    SUM(CASE WHEN rc.used_at IS NULL THEN 1 ELSE 0 END) AS remaining,
                    MAX(rc.used_at) AS last_used_at
                FROM recovery_code_batches rcb
                LEFT JOIN recovery_codes rc ON rc.batch_id = rcb.id
                WHERE rcb.binding = :binding
                  AND rcb.revoked_at IS NULL'
           );

           $statement->execute(['binding' => $binding]);
           $row = $statement->fetch(PDO::FETCH_ASSOC);

           if (!is_array($row) || $row['total'] === null) {
               return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
           }

           return [
               'total' => (int) $row['total'],
               'remaining' => (int) $row['remaining'],
               'lastUsedAt' => $row['last_used_at'] !== null
                   ? new DateTimeImmutable((string) $row['last_used_at'], new DateTimeZone('UTC'))
                   : null,
           ];
       }
   }

Using the store
~~~~~~~~~~~~~~~

.. code-block:: php

   use Infocyph\OTP\RecoveryCodes;

   $store = new PdoRecoveryCodeStore($pdo);
   $codes = new RecoveryCodes($store);

   $generated = $codes->generate('user-42');
   $result = $codes->consume('user-42', $generated->plainCodes[0]);

Replay tracking in a database
-----------------------------

Recommended schema
~~~~~~~~~~~~~~~~~~

One simple design uses two tables:

- one for current replay state
- one for consumed tokens

Example schema:

.. code-block:: sql

   CREATE TABLE otp_replay_state (
       namespace VARCHAR(100) NOT NULL,
       binding VARCHAR(190) NOT NULL,
       state_value VARCHAR(255) NULL,
       updated_at TIMESTAMP NOT NULL,
       PRIMARY KEY (namespace, binding)
   );

   CREATE TABLE otp_replay_consumed (
       namespace VARCHAR(100) NOT NULL,
       binding VARCHAR(190) NOT NULL,
       token VARCHAR(255) NOT NULL,
       expires_at TIMESTAMP NULL,
       PRIMARY KEY (namespace, binding, token)
   );

Example PDO store
~~~~~~~~~~~~~~~~~

.. code-block:: php

   <?php

   declare(strict_types=1);

   use DateTimeImmutable;
   use DateTimeZone;
   use Infocyph\OTP\Contracts\ReplayStoreInterface;
   use PDO;

   final readonly class PdoReplayStore implements ReplayStoreInterface
   {
       public function __construct(
           private PDO $pdo,
       ) {}

       public function hasConsumed(string $namespace, string $binding, string $token): bool
       {
           $statement = $this->pdo->prepare(
               'SELECT expires_at
                FROM otp_replay_consumed
                WHERE namespace = :namespace
                  AND binding = :binding
                  AND token = :token'
           );

           $statement->execute([
               'namespace' => $namespace,
               'binding' => $binding,
               'token' => $token,
           ]);

           $row = $statement->fetch(PDO::FETCH_ASSOC);
           if (!is_array($row)) {
               return false;
           }

           if ($row['expires_at'] !== null) {
               $expiresAt = new DateTimeImmutable((string) $row['expires_at'], new DateTimeZone('UTC'));
               if ($expiresAt <= new DateTimeImmutable('now', new DateTimeZone('UTC'))) {
                   return false;
               }
           }

           return true;
       }

       public function markConsumed(string $namespace, string $binding, string $token, ?int $ttl = null): void
       {
           $expiresAt = $ttl !== null
               ? (new DateTimeImmutable('now', new DateTimeZone('UTC')))->modify("+{$ttl} seconds")->format('Y-m-d H:i:s')
               : null;

           $statement = $this->pdo->prepare(
               'INSERT INTO otp_replay_consumed (namespace, binding, token, expires_at)
                VALUES (:namespace, :binding, :token, :expires_at)'
           );

           $statement->execute([
               'namespace' => $namespace,
               'binding' => $binding,
               'token' => $token,
               'expires_at' => $expiresAt,
           ]);
       }

       public function getState(string $namespace, string $binding): int|string|null
       {
           $statement = $this->pdo->prepare(
               'SELECT state_value
                FROM otp_replay_state
                WHERE namespace = :namespace
                  AND binding = :binding'
           );

           $statement->execute([
               'namespace' => $namespace,
               'binding' => $binding,
           ]);

           $row = $statement->fetch(PDO::FETCH_ASSOC);
           if (!is_array($row) || $row['state_value'] === null) {
               return null;
           }

           $value = (string) $row['state_value'];

           return ctype_digit($value) ? (int) $value : $value;
       }

       public function setState(string $namespace, string $binding, int|string|null $value, ?int $ttl = null): void
       {
           $statement = $this->pdo->prepare(
               'MERGE INTO otp_replay_state AS target
                USING (SELECT :namespace AS namespace, :binding AS binding) AS source
                ON (target.namespace = source.namespace AND target.binding = source.binding)
                WHEN MATCHED THEN
                    UPDATE SET state_value = :state_value, updated_at = :updated_at
                WHEN NOT MATCHED THEN
                    INSERT (namespace, binding, state_value, updated_at)
                    VALUES (:namespace, :binding, :state_value, :updated_at);'
           );

           $statement->execute([
               'namespace' => $namespace,
               'binding' => $binding,
               'state_value' => $value !== null ? (string) $value : null,
               'updated_at' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
           ]);
       }
   }

Using the replay store
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   use Infocyph\OTP\Stores\InMemoryReplayStore;
   use Infocyph\OTP\TOTP;
   use Infocyph\OTP\ValueObjects\VerificationWindow;

   $totp = new TOTP($secret);
   $store = new PdoReplayStore($pdo);

   $result = $totp->verifyWithWindow(
       $submittedOtp,
       window: new VerificationWindow(past: 1, future: 1),
       replayStore: $store,
       binding: 'user-42',
   );

Notes
-----

- The SQL above is illustrative. You may need to adapt syntax for PostgreSQL, MySQL, SQLite or SQL Server.
- Recovery code consumption should be atomic to prevent double-use under concurrency.
- Replay stores should apply indexes on namespace, binding and token.
- Recovery code hashes should be treated as sensitive authentication data even though they are hashed.
