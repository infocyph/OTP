<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\Base64Url;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\GridChallenge;
use InvalidArgumentException;
use RuntimeException;

final readonly class GridOTP
{
    private const int ISSUE_ATTEMPTS = 4;

    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_TTL_SECONDS = 900;

    private const int STATE_VERSION = 1;

    public function __construct(
        private AuthenticationStateCacheInterface $cache,
        #[\SensitiveParameter]
        private string $secret,
        private int $challengeSize = 6,
        private int $ttlSeconds = 120,
        private int $maxAttempts = 3,
    ) {
        self::assertSecret($secret);
        if ($challengeSize < 6 || $challengeSize > 10 || $challengeSize > strlen($secret)) {
            throw new InvalidArgumentException('GridOTP challenge size must be between 6 and 10 and not exceed the secret length.');
        }
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('GridOTP challenge TTL must be between 1 and 900 seconds.');
        }
        if ($maxAttempts < 1 || $maxAttempts > 10) {
            throw new InvalidArgumentException('GridOTP max attempts must be between 1 and 10.');
        }
        CacheLock::assertLockSafe($cache);
    }

    public static function generateSecret(int $length = 12): string
    {
        if ($length < 8 || $length > 32) {
            throw new InvalidArgumentException('GridOTP generated secrets must contain between 8 and 32 symbols.');
        }
        $alphabet = GridChallenge::SECRET_ALPHABET;
        $bytes = random_bytes($length);
        $secret = '';
        for ($index = 0; $index < $length; $index++) {
            $secret .= $alphabet[ord($bytes[$index]) & 31];
        }

        return $secret;
    }

    public static function respond(
        GridChallenge $challenge,
        #[\SensitiveParameter]
        string $secret,
    ): string {
        self::assertSecret($secret);
        if (strlen($secret) !== $challenge->secretLength) {
            throw new InvalidArgumentException('GridOTP secret length does not match the challenge.');
        }

        $response = '';
        foreach ($challenge->positions as $position) {
            $symbol = $secret[$position - 1];
            $response .= $challenge->grid[$symbol];
        }

        return $response;
    }

    public function issue(string $factorId, ?int $now = null): GridChallenge
    {
        self::assertFactorId($factorId);
        for ($attempt = 0; $attempt < self::ISSUE_ATTEMPTS; $attempt++) {
            $id = Base64Url::encode(random_bytes(16));
            $stateKey = self::stateKey($factorId, $id);
            $challenge = CacheLock::synchronized(
                $this->cache,
                self::lockKey($factorId, $id),
                function (LockProviderInterface $locks, LockHandle $handle) use ($id, $stateKey, $now): ?GridChallenge {
                    if ($this->cache->get($stateKey) !== null) {
                        return null;
                    }
                    $issuedAt = $now ?? time();
                    if ($issuedAt < 0 || $issuedAt > PHP_INT_MAX - $this->ttlSeconds) {
                        throw new InvalidArgumentException('GridOTP challenge expiration exceeds the supported timestamp range.');
                    }
                    $challenge = new GridChallenge(
                        $id,
                        self::randomGrid(),
                        self::randomPositions(strlen($this->secret), $this->challengeSize),
                        strlen($this->secret),
                        $issuedAt,
                        $issuedAt + $this->ttlSeconds,
                    );
                    $state = [
                        'v' => self::STATE_VERSION,
                        'digest' => hash('sha256', $challenge->canonicalPayload()),
                        'remainingAttempts' => $this->maxAttempts,
                        'expiresAt' => $challenge->expiresAt,
                        'consumed' => false,
                    ];
                    CacheLock::ensureOwned($locks, $handle);
                    if (!$this->cache->set($stateKey, $state, $this->ttlSeconds)) {
                        throw new RuntimeException('Unable to store GridOTP challenge state.');
                    }

                    return $challenge;
                },
            );
            if ($challenge !== null) {
                return $challenge;
            }
        }

        throw new RuntimeException('Unable to reserve a unique GridOTP challenge.');
    }

    public function verify(
        string $factorId,
        GridChallenge $challenge,
        #[\SensitiveParameter]
        string $response,
        ?int $now = null,
    ): bool {
        return $this->verifyWithResult($factorId, $challenge, $response, $now)->matched;
    }

    public function verifyWithResult(
        string $factorId,
        GridChallenge $challenge,
        #[\SensitiveParameter]
        string $response,
        ?int $now = null,
    ): VerificationResult {
        self::assertFactorId($factorId);
        if (strlen($response) !== count($challenge->positions) || !ctype_digit($response)) {
            return VerificationResult::malformed();
        }
        $now ??= time();
        if ($now < 0) {
            throw new InvalidArgumentException('GridOTP verification timestamp must be non-negative.');
        }

        return CacheLock::synchronized(
            $this->cache,
            self::lockKey($factorId, $challenge->id),
            fn(LockProviderInterface $locks, LockHandle $handle): VerificationResult => $this->verifyLocked(
                $factorId,
                $challenge,
                $response,
                $now,
                $locks,
                $handle,
            ),
        );
    }

    private static function assertFactorId(string $factorId): void
    {
        if ($factorId === '' || strlen($factorId) > self::MAX_FACTOR_ID_LENGTH) {
            throw new InvalidArgumentException('Factor IDs must contain between 1 and 190 bytes.');
        }
    }

    private static function assertSecret(string $secret): void
    {
        $length = strlen($secret);
        if (
            $length < 8
            || $length > 32
            || strspn($secret, GridChallenge::SECRET_ALPHABET) !== $length
        ) {
            throw new InvalidArgumentException(
                'GridOTP secrets must contain 8 to 32 symbols from ' . GridChallenge::SECRET_ALPHABET . '.',
            );
        }
    }

    private static function lockKey(string $factorId, string $challengeId): string
    {
        return hash('sha256', "infocyph:otp:gridotp:lock:v1\0" . $factorId . "\0" . $challengeId);
    }

    /** @return array<array-key, string> */
    private static function randomGrid(): array
    {
        $labels = self::shuffleSecure(str_split(GridChallenge::RESPONSE_ALPHABET));
        $balanced = [];
        $labelCount = count($labels);
        $alphabetLength = strlen(GridChallenge::SECRET_ALPHABET);
        for ($index = 0; $index < $alphabetLength; $index++) {
            $balanced[] = $labels[$index % $labelCount];
        }
        $balanced = self::shuffleSecure($balanced);

        $grid = [];
        foreach (str_split(GridChallenge::SECRET_ALPHABET) as $index => $symbol) {
            $grid[$symbol] = $balanced[$index];
        }

        return $grid;
    }

    /** @return list<int> */
    private static function randomPositions(int $secretLength, int $challengeSize): array
    {
        $positions = self::shuffleSecure(range(1, $secretLength));

        return array_slice($positions, 0, $challengeSize);
    }

    /**
     * @template T
     * @param list<T> $values
     * @return list<T>
     */
    private static function shuffleSecure(array $values): array
    {
        for ($index = count($values) - 1; $index > 0; $index--) {
            $swap = random_int(0, $index);
            [$values[$index], $values[$swap]] = [$values[$swap], $values[$index]];
        }

        return $values;
    }

    private static function stateKey(string $factorId, string $challengeId): string
    {
        return hash('sha256', "infocyph:otp:gridotp:state:v1\0" . $factorId . "\0" . $challengeId);
    }

    private function deleteLocked(string $stateKey, LockProviderInterface $locks, LockHandle $handle): void
    {
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->delete($stateKey)) {
            throw new RuntimeException('Unable to delete GridOTP challenge state.');
        }
    }

    /** @return array{v:int,digest:string,remainingAttempts:int,expiresAt:int,consumed:bool} */
    private function requireState(mixed $state): array
    {
        if (!is_array($state) || count($state) !== 5) {
            throw new RuntimeException('Invalid GridOTP challenge state in CacheLayer.');
        }

        $version = $state['v'] ?? null;
        $digest = $state['digest'] ?? null;
        $remainingAttempts = $state['remainingAttempts'] ?? null;
        $expiresAt = $state['expiresAt'] ?? null;
        $consumed = $state['consumed'] ?? null;
        if (
            $version !== self::STATE_VERSION
            || !is_string($digest)
            || preg_match('/\A[0-9a-f]{64}\z/D', $digest) !== 1
            || !is_int($remainingAttempts)
            || $remainingAttempts < 1
            || $remainingAttempts > $this->maxAttempts
            || !is_int($expiresAt)
            || $expiresAt < 0
            || !is_bool($consumed)
        ) {
            throw new RuntimeException('Invalid GridOTP challenge state in CacheLayer.');
        }

        return [
            'v' => $version,
            'digest' => $digest,
            'remainingAttempts' => $remainingAttempts,
            'expiresAt' => $expiresAt,
            'consumed' => $consumed,
        ];
    }

    /** @param array{v:int,digest:string,remainingAttempts:int,expiresAt:int,consumed:bool} $state */
    private function storeLocked(
        string $stateKey,
        array $state,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): void {
        $ttl = $state['expiresAt'] - $now;
        if ($ttl < 1) {
            throw new RuntimeException('GridOTP challenge state expired before mutation.');
        }
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->set($stateKey, $state, $ttl)) {
            throw new RuntimeException('Unable to update GridOTP challenge state.');
        }
    }

    private function verifyLocked(
        string $factorId,
        GridChallenge $challenge,
        string $response,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): VerificationResult {
        $stateKey = self::stateKey($factorId, $challenge->id);
        $stored = $this->cache->get($stateKey);
        if ($stored === null) {
            return VerificationResult::mismatch();
        }
        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now || $challenge->expiresAt <= $now) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return VerificationResult::mismatch();
        }
        if ($state['consumed']) {
            return VerificationResult::replay();
        }
        if (
            $challenge->issuedAt > $now
            || $challenge->secretLength !== strlen($this->secret)
            || count($challenge->positions) !== $this->challengeSize
            || !hash_equals($state['digest'], hash('sha256', $challenge->canonicalPayload()))
        ) {
            return VerificationResult::mismatch();
        }

        $expected = self::respond($challenge, $this->secret);
        if (hash_equals($expected, $response)) {
            $state['consumed'] = true;
            $this->storeLocked($stateKey, $state, $now, $locks, $handle);

            return VerificationResult::success();
        }

        $remaining = $state['remainingAttempts'] - 1;
        if ($remaining === 0) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return VerificationResult::mismatch();
        }
        $state['remainingAttempts'] = $remaining;
        $this->storeLocked($stateKey, $state, $now, $locks, $handle);

        return VerificationResult::mismatch();
    }
}
