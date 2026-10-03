<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use Infocyph\OTP\Support\CacheLock;
use InvalidArgumentException;
use RuntimeException;

final readonly class GenericOtp
{
    private const int MAX_BINDING_LENGTH = 4096;

    private const int MAX_KEY_LENGTH = 1024;

    private const int MAX_TTL_SECONDS = 86400;

    private const int STATE_VERSION = 1;

    public function __construct(
        private AuthenticationStateCacheInterface $cache,
        #[\SensitiveParameter]
        private string $key,
        private int $digits = 6,
        private int $ttlSeconds = 300,
        private int $maxAttempts = 3,
    ) {
        if ($digits < 6 || $digits > 10) {
            throw new InvalidArgumentException('Generic OTP digit count must be between 6 and 10.');
        }
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('Generic OTP validity must be between 1 and 86400 seconds.');
        }
        if ($maxAttempts < 1 || $maxAttempts > 10) {
            throw new InvalidArgumentException('Generic OTP max attempts must be between 1 and 10.');
        }
        if (strlen($key) < 16 || strlen($key) > self::MAX_KEY_LENGTH) {
            throw new InvalidArgumentException('Generic OTP HMAC keys must contain between 16 and 1024 bytes.');
        }
        CacheLock::assertSafe($cache);
    }

    /** @return array{cache:string,key:string,digits:int,ttlSeconds:int,maxAttempts:int} */
    public function __debugInfo(): array
    {
        return [
            'cache' => get_debug_type($this->cache),
            'key' => '[redacted]',
            'digits' => $this->digits,
            'ttlSeconds' => $this->ttlSeconds,
            'maxAttempts' => $this->maxAttempts,
        ];
    }

    public function delete(string $binding, ?RunwireExecutionContext $runwire = null): bool {
        self::assertBinding($binding);
        CacheLock::checkpoint($runwire);
        $stateKey = self::stateKey($binding);
        if (($atomic = CacheLock::stateAtomic($this->cache)) !== null) {
            $atomic->getAndDelete($stateKey);

            return true;
        }

        return CacheLock::synchronized($this->cache, self::lockKey($binding), function (
            LockProviderInterface $locks,
            LockHandle $handle,
        ) use ($stateKey): bool {
            CacheLock::ensureOwned($locks, $handle);
            if (!$this->cache->delete($stateKey)) {
                throw new RuntimeException('Unable to delete generic OTP state.');
            }

            return true;
        }, $runwire);
    }

    public function generate(string $binding, ?RunwireExecutionContext $runwire = null): string
    {
        self::assertBinding($binding);
        $otp = self::randomDigits($this->digits);
        CacheLock::transition(
            $this->cache,
            self::stateKey($binding),
            self::lockKey($binding),
            'generic OTP',
            function (mixed $current) use ($binding, $otp): array {
                unset($current);
                $now = time();
                if ($now > PHP_INT_MAX - $this->ttlSeconds) {
                    throw new InvalidArgumentException('Generic OTP expiration exceeds the supported timestamp range.');
                }

                return [
                    'result' => null,
                    'replacement' => [
                        'v' => self::STATE_VERSION,
                        'digest' => $this->digest($binding, $otp),
                        'remainingAttempts' => $this->maxAttempts,
                        'expiresAt' => $now + $this->ttlSeconds,
                    ],
                    'ttl' => $this->ttlSeconds,
                    'failure' => 'Unable to store generic OTP state.',
                ];
            },
            $runwire,
        );

        return $otp;
    }

    public function verify(
        string $binding,
        #[\SensitiveParameter]
        string $otp,
        ?RunwireExecutionContext $runwire = null,
    ): bool {
        self::assertBinding($binding);
        if (strlen($otp) !== $this->digits || !ctype_digit($otp)) {
            return false;
        }

        $candidateDigest = $this->digest($binding, $otp);
        $now = time();

        return CacheLock::transition(
            $this->cache,
            self::stateKey($binding),
            self::lockKey($binding),
            'generic OTP',
            fn(mixed $stored): array => $this->verifyState($stored, $candidateDigest, $now),
            $runwire,
        );
    }

    private static function assertBinding(string $binding): void
    {
        if ($binding === '' || strlen($binding) > self::MAX_BINDING_LENGTH) {
            throw new InvalidArgumentException('Generic OTP bindings must contain between 1 and 4096 bytes.');
        }
    }

    private static function lockKey(string $binding): string
    {
        return hash('sha256', "infocyph:otp:generic:lock:v1\0" . $binding);
    }

    private static function randomDigits(int $length): string
    {
        $number = '';
        while (strlen($number) < $length) {
            $bytes = random_bytes(max(1, $length - strlen($number)));
            $byteCount = strlen($bytes);
            for ($index = 0; $index < $byteCount; $index++) {
                $value = ord($bytes[$index]);
                if ($value < 250) {
                    $number .= chr(48 + ($value % 10));
                }
            }
        }

        return $number;
    }

    private static function stateKey(string $binding): string
    {
        return hash('sha256', "infocyph:otp:generic:state:v1\0" . $binding);
    }

    private function digest(string $binding, string $otp): string
    {
        return hash_hmac('sha256', "generic-otp\0" . $binding . "\0" . $otp, $this->key);
    }

    /**
     * @param mixed $state Untrusted state loaded from CacheLayer.
     * @return array{v:int,digest:string,remainingAttempts:int,expiresAt:int}
     */
    private function requireState(mixed $state): array
    {
        if (
            !is_array($state)
            || count($state) !== 4
            || ($state['v'] ?? null) !== self::STATE_VERSION
            || !is_string($state['digest'] ?? null)
            || preg_match('/\A[0-9a-f]{64}\z/D', $state['digest']) !== 1
            || !is_int($state['remainingAttempts'] ?? null)
            || $state['remainingAttempts'] < 1
            || $state['remainingAttempts'] > $this->maxAttempts
            || !is_int($state['expiresAt'] ?? null)
            || $state['expiresAt'] < 0
        ) {
            throw new RuntimeException('Invalid generic OTP state in CacheLayer.');
        }

        return $state;
    }

    /**
     * @return array{
     *     result:bool,
     *     replacement?:array{v:int,digest:string,remainingAttempts:int,expiresAt:int},
     *     ttl?:int,
     *     delete?:bool,
     *     failure?:string
     * }
     */
    private function verifyState(mixed $stored, string $candidateDigest, int $now): array
    {
        if ($stored === null) {
            return ['result' => false];
        }

        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now) {
            $state['expiresAt'] = $now;

            return [
                'result' => false,
                'replacement' => $state,
                'ttl' => 1,
                'delete' => true,
                'failure' => 'Unable to delete generic OTP state.',
            ];
        }
        if (hash_equals($state['digest'], $candidateDigest)) {
            $state['expiresAt'] = $now;

            return [
                'result' => true,
                'replacement' => $state,
                'ttl' => 1,
                'delete' => true,
                'failure' => 'Unable to delete generic OTP state.',
            ];
        }

        $remaining = $state['remainingAttempts'] - 1;
        if ($remaining === 0) {
            $state['expiresAt'] = $now;

            return [
                'result' => false,
                'replacement' => $state,
                'ttl' => 1,
                'delete' => true,
                'failure' => 'Unable to delete generic OTP state.',
            ];
        }

        $state['remainingAttempts'] = $remaining;

        return [
            'result' => false,
            'replacement' => $state,
            'ttl' => $state['expiresAt'] - $now,
            'failure' => 'Unable to update generic OTP state.',
        ];
    }
}
