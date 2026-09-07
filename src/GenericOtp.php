<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
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
        CacheLock::assertLockSafe($cache);
    }

    public function delete(string $binding): bool
    {
        self::assertBinding($binding);

        return CacheLock::synchronized($this->cache, self::lockKey($binding), function (
            LockProviderInterface $locks,
            LockHandle $handle,
        ) use ($binding): bool {
            CacheLock::ensureOwned($locks, $handle);
            if (!$this->cache->delete(self::stateKey($binding))) {
                throw new RuntimeException('Unable to delete generic OTP state.');
            }

            return true;
        });
    }

    public function generate(string $binding): string
    {
        self::assertBinding($binding);
        $otp = self::randomDigits($this->digits);
        CacheLock::synchronized($this->cache, self::lockKey($binding), function (
            LockProviderInterface $locks,
            LockHandle $handle,
        ) use ($binding, $otp): void {
            CacheLock::ensureOwned($locks, $handle);
            $now = time();
            if ($now > PHP_INT_MAX - $this->ttlSeconds) {
                throw new InvalidArgumentException('Generic OTP expiration exceeds the supported timestamp range.');
            }
            if (!$this->cache->set(self::stateKey($binding), [
                'v' => self::STATE_VERSION,
                'digest' => $this->digest($binding, $otp),
                'remainingAttempts' => $this->maxAttempts,
                'expiresAt' => $now + $this->ttlSeconds,
            ], $this->ttlSeconds)) {
                throw new RuntimeException('Unable to store generic OTP state.');
            }
        });

        return $otp;
    }

    public function verify(string $binding, #[\SensitiveParameter] string $otp): bool
    {
        self::assertBinding($binding);
        if (strlen($otp) !== $this->digits || !ctype_digit($otp)) {
            return false;
        }

        $candidateDigest = $this->digest($binding, $otp);

        return CacheLock::synchronized($this->cache, self::lockKey($binding), fn(
            LockProviderInterface $locks,
            LockHandle $handle,
        ): bool => $this->verifyLocked($binding, $candidateDigest, time(), $locks, $handle));
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

    private function deleteLocked(
        string $stateKey,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): void {
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->delete($stateKey)) {
            throw new RuntimeException('Unable to delete generic OTP state.');
        }
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

    private function verifyLocked(
        string $binding,
        string $candidateDigest,
        int $now,
        LockProviderInterface $locks,
        LockHandle $handle,
    ): bool {
        $stateKey = self::stateKey($binding);
        $stored = $this->cache->get($stateKey);
        if ($stored === null) {
            return false;
        }

        $state = $this->requireState($stored);
        if ($state['expiresAt'] <= $now) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return false;
        }
        if (hash_equals($state['digest'], $candidateDigest)) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return true;
        }

        $remaining = $state['remainingAttempts'] - 1;
        if ($remaining === 0) {
            $this->deleteLocked($stateKey, $locks, $handle);

            return false;
        }

        $state['remainingAttempts'] = $remaining;
        CacheLock::ensureOwned($locks, $handle);
        if (!$this->cache->set($stateKey, $state, $state['expiresAt'] - $now)) {
            throw new RuntimeException('Unable to update generic OTP state.');
        }

        return false;
    }
}
