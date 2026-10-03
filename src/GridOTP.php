<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
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
        private bool $enforceDiversity = false,
    ) {
        self::assertSecret($secret);
        self::assertChallengeSize($challengeSize, strlen($secret));
        if ($enforceDiversity && self::uniqueSymbolCount($secret) < $challengeSize) {
            throw new InvalidArgumentException(
                'GridOTP diversity enforcement requires at least one distinct secret symbol per challenge position.',
            );
        }
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('GridOTP challenge TTL must be between 1 and 900 seconds.');
        }
        if ($maxAttempts < 1 || $maxAttempts > 10) {
            throw new InvalidArgumentException('GridOTP max attempts must be between 1 and 10.');
        }
        CacheLock::assertSafe($cache);
    }

    /** @return array{cache:string,secret:string,challengeSize:int,ttlSeconds:int,maxAttempts:int,enforceDiversity:bool} */
    public function __debugInfo(): array
    {
        return [
            'cache' => get_debug_type($this->cache),
            'secret' => '[redacted]',
            'challengeSize' => $this->challengeSize,
            'ttlSeconds' => $this->ttlSeconds,
            'maxAttempts' => $this->maxAttempts,
            'enforceDiversity' => $this->enforceDiversity,
        ];
    }

    public static function generateSecret(int $length = 12): string
    {
        if ($length < 8 || $length > 32) {
            throw new InvalidArgumentException('GridOTP generated secrets must contain between 8 and 32 symbols.');
        }
        $alphabet = str_split(GridChallenge::SECRET_ALPHABET);
        $requiredDiversity = min(10, $length);
        $symbols = array_slice(self::shuffleSecure($alphabet), 0, $requiredDiversity);
        for ($index = $requiredDiversity; $index < $length; $index++) {
            $symbols[] = $alphabet[random_int(0, count($alphabet) - 1)];
        }

        return implode('', self::shuffleSecure($symbols));
    }

    public static function hasSufficientDiversity(string $secret, int $challengeSize = 6): bool
    {
        self::assertSecret($secret);
        self::assertChallengeSize($challengeSize, strlen($secret));

        return self::uniqueSymbolCount($secret) >= $challengeSize;
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
            $challenge = CacheLock::transition(
                $this->cache,
                self::stateKey($factorId, $id),
                self::lockKey($factorId, $id),
                'GridOTP challenge',
                fn(mixed $stored): array => $this->issueState($stored, $id, $now),
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

        return CacheLock::transition(
            $this->cache,
            self::stateKey($factorId, $challenge->id),
            self::lockKey($factorId, $challenge->id),
            'GridOTP challenge',
            fn(mixed $stored): array => $this->verifyState($stored, $challenge, $response, $now),
        );
    }

    private static function assertChallengeSize(int $challengeSize, int $secretLength): void
    {
        if ($challengeSize < 6 || $challengeSize > 10 || $challengeSize > $secretLength) {
            throw new InvalidArgumentException(
                'GridOTP challenge size must be between 6 and 10 and not exceed the secret length.',
            );
        }
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
    private static function randomPositions(string $secret, int $challengeSize): array
    {
        $positionsBySymbol = [];
        $secretLength = strlen($secret);
        for ($index = 0; $index < $secretLength; $index++) {
            $positionsBySymbol[$secret[$index]][] = $index + 1;
        }
        if (count($positionsBySymbol) < $challengeSize) {
            return array_slice(self::shuffleSecure(range(1, $secretLength)), 0, $challengeSize);
        }

        $symbols = array_slice(self::shuffleSecure(array_keys($positionsBySymbol)), 0, $challengeSize);
        $positions = [];
        foreach ($symbols as $symbol) {
            $candidates = $positionsBySymbol[$symbol];
            $positions[] = $candidates[random_int(0, count($candidates) - 1)];
        }

        return $positions;
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

        return array_values($values);
    }

    private static function stateKey(string $factorId, string $challengeId): string
    {
        return hash('sha256', "infocyph:otp:gridotp:state:v1\0" . $factorId . "\0" . $challengeId);
    }

    private static function uniqueSymbolCount(string $secret): int
    {
        return count(array_unique(str_split($secret)));
    }

    /**
     * @return array{
     *     result:GridChallenge|null,
     *     replacement?:array{v:int,digest:string,remainingAttempts:int,expiresAt:int,consumed:bool},
     *     ttl?:int,
     *     failure?:string
     * }
     */
    private function issueState(mixed $stored, string $id, ?int $now): array
    {
        if ($stored !== null) {
            return ['result' => null];
        }

        $issuedAt = $now ?? time();
        if ($issuedAt < 0 || $issuedAt > PHP_INT_MAX - $this->ttlSeconds) {
            throw new InvalidArgumentException('GridOTP challenge expiration exceeds the supported timestamp range.');
        }
        $challenge = new GridChallenge(
            $id,
            self::randomGrid(),
            self::randomPositions($this->secret, $this->challengeSize),
            strlen($this->secret),
            $issuedAt,
            $issuedAt + $this->ttlSeconds,
        );

        return [
            'result' => $challenge,
            'replacement' => [
                'v' => self::STATE_VERSION,
                'digest' => hash('sha256', $challenge->canonicalPayload()),
                'remainingAttempts' => $this->maxAttempts,
                'expiresAt' => $challenge->expiresAt,
                'consumed' => false,
            ],
            'ttl' => $this->ttlSeconds,
            'failure' => 'Unable to store GridOTP challenge state.',
        ];
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

    /**
     * @return array{
     *     result:VerificationResult,
     *     replacement?:array{v:int,digest:string,remainingAttempts:int,expiresAt:int,consumed:bool},
     *     ttl?:int,
     *     delete?:bool,
     *     failure?:string
     * }
     */
    private function verifyState(
        mixed $stored,
        GridChallenge $challenge,
        string $response,
        int $now,
    ): array {
        if ($stored === null) {
            return ['result' => VerificationResult::mismatch()];
        }
        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now || $challenge->expiresAt <= $now) {
            $state['expiresAt'] = $now;

            return [
                'result' => VerificationResult::mismatch(),
                'replacement' => $state,
                'ttl' => 1,
                'delete' => true,
                'failure' => 'Unable to delete GridOTP challenge state.',
            ];
        }
        if ($state['consumed']) {
            return ['result' => VerificationResult::replay()];
        }
        if (
            $challenge->issuedAt > $now
            || $challenge->secretLength !== strlen($this->secret)
            || count($challenge->positions) !== $this->challengeSize
            || !hash_equals($state['digest'], hash('sha256', $challenge->canonicalPayload()))
        ) {
            return ['result' => VerificationResult::mismatch()];
        }

        if (hash_equals(self::respond($challenge, $this->secret), $response)) {
            $state['consumed'] = true;

            return [
                'result' => VerificationResult::success(),
                'replacement' => $state,
                'ttl' => $state['expiresAt'] - $now,
                'failure' => 'Unable to update GridOTP challenge state.',
            ];
        }

        $remaining = $state['remainingAttempts'] - 1;
        if ($remaining === 0) {
            $state['expiresAt'] = $now;

            return [
                'result' => VerificationResult::mismatch(),
                'replacement' => $state,
                'ttl' => 1,
                'delete' => true,
                'failure' => 'Unable to delete GridOTP challenge state.',
            ];
        }
        $state['remainingAttempts'] = $remaining;

        return [
            'result' => VerificationResult::mismatch(),
            'replacement' => $state,
            'ttl' => $state['expiresAt'] - $now,
            'failure' => 'Unable to update GridOTP challenge state.',
        ];
    }

}
