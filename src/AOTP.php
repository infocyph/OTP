<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\Base64Url;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\AotpChallenge;
use Infocyph\OTP\ValueObjects\AotpKeyPair;
use Infocyph\OTP\ValueObjects\AotpResponse;
use InvalidArgumentException;
use LogicException;
use RuntimeException;

final readonly class AOTP
{
    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_TTL_SECONDS = 600;

    private const int PRIVATE_KEY_BYTES = 64;

    private const int PUBLIC_KEY_BYTES = 32;

    private const int RESERVATION_ATTEMPTS = 4;

    private const int SIGNATURE_BYTES = 64;

    /** @var non-empty-string */
    private string $binaryPublicKey;

    public function __construct(
        string $publicKey,
        private string $audience,
    ) {
        self::requireSodium();
        $this->binaryPublicKey = self::decodeKey($publicKey, self::PUBLIC_KEY_BYTES, 'AOTP public key');
        self::assertAudience($audience);
    }

    public static function generateKeyPair(): AotpKeyPair
    {
        self::requireSodium();
        $pair = sodium_crypto_sign_keypair();
        $binaryPrivateKey = sodium_crypto_sign_secretkey($pair);
        $encodedPublicKey = self::encode(sodium_crypto_sign_publickey($pair));
        $encodedPrivateKey = self::encode($binaryPrivateKey);
        sodium_memzero($binaryPrivateKey);
        sodium_memzero($pair);

        return new AotpKeyPair($encodedPublicKey, $encodedPrivateKey);
    }

    public static function isAvailable(): bool
    {
        return function_exists('sodium_crypto_sign_keypair')
            && function_exists('sodium_crypto_sign_publickey')
            && function_exists('sodium_crypto_sign_secretkey')
            && function_exists('sodium_crypto_sign_detached')
            && function_exists('sodium_crypto_sign_verify_detached')
            && function_exists('sodium_memzero');
    }

    public static function respond(
        #[\SensitiveParameter]
        string $privateKey,
        AotpChallenge $challenge,
        string $expectedAudience,
        string $expectedContext,
        ?int $now = null,
    ): AotpResponse {
        self::requireSodium();
        self::assertAudience($expectedAudience);
        self::assertContext($expectedContext);
        if (!hash_equals($expectedAudience, $challenge->audience)) {
            throw new InvalidArgumentException('AOTP challenge audience does not match the expected verifier.');
        }
        if (!hash_equals($expectedContext, $challenge->context)) {
            throw new InvalidArgumentException('AOTP challenge context does not match the expected operation.');
        }

        $now ??= time();
        if ($now < 0) {
            throw new InvalidArgumentException('AOTP signing timestamp must be non-negative.');
        }
        if ($challenge->issuedAt > $now || $challenge->expiresAt <= $now) {
            throw new InvalidArgumentException('AOTP challenge is not currently valid for signing.');
        }

        $binaryPrivateKey = self::decodeKey(
            $privateKey,
            self::PRIVATE_KEY_BYTES,
            'AOTP private key',
        );
        try {
            $signature = sodium_crypto_sign_detached($challenge->signingPayload(), $binaryPrivateKey);
        } finally {
            sodium_memzero($binaryPrivateKey);
        }

        return new AotpResponse($challenge->id, self::encode($signature));
    }

    public function issue(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        string $context,
        int $ttlSeconds = 120,
        ?int $now = null,
    ): AotpChallenge {
        self::assertFactorId($factorId);
        self::assertContext($context);
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS) {
            throw new InvalidArgumentException('AOTP challenge TTL must be between 1 and 600 seconds.');
        }
        CacheLock::assertSafe($cache);

        for ($attempt = 0; $attempt < self::RESERVATION_ATTEMPTS; $attempt++) {
            $issuedAt = $now ?? time();
            if ($issuedAt < 0 || $issuedAt > PHP_INT_MAX - $ttlSeconds) {
                throw new InvalidArgumentException('AOTP challenge expiration exceeds the supported timestamp range.');
            }
            $challenge = new AotpChallenge(
                self::encode(random_bytes(16)),
                self::encode(random_bytes(32)),
                $this->audience,
                $context,
                $issuedAt,
                $issuedAt + $ttlSeconds,
            );
            if (CacheLock::reserveOnce(
                $cache,
                self::stateKey($factorId, $challenge),
                self::lockKey($factorId, $challenge),
                $ttlSeconds,
                'AOTP challenge',
            )) {
                return $challenge;
            }
        }

        throw new RuntimeException('Unable to reserve a unique AOTP challenge.');
    }

    public function verify(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        AotpChallenge $challenge,
        AotpResponse $response,
        ?int $now = null,
    ): bool {
        return $this->verifyWithResult($cache, $factorId, $challenge, $response, $now)->matched;
    }

    public function verifyWithResult(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        AotpChallenge $challenge,
        AotpResponse $response,
        ?int $now = null,
    ): VerificationResult {
        self::assertFactorId($factorId);
        CacheLock::assertSafe($cache);
        $now ??= time();
        if ($now < 0) {
            throw new InvalidArgumentException('AOTP verification timestamp must be non-negative.');
        }
        if (
            !hash_equals($challenge->id, $response->challengeId)
            || !hash_equals($this->audience, $challenge->audience)
            || $challenge->issuedAt > $now
            || $challenge->expiresAt <= $now
        ) {
            return VerificationResult::mismatch();
        }

        $stateKey = self::stateKey($factorId, $challenge);
        $state = $cache->get($stateKey);
        if ($state === null) {
            return VerificationResult::mismatch();
        }
        if (!is_int($state) || ($state !== 0 && $state !== 1)) {
            throw new RuntimeException('Invalid AOTP challenge state in CacheLayer.');
        }

        $signature = self::decodeSignature($response->signature);
        if (!sodium_crypto_sign_verify_detached($signature, $challenge->signingPayload(), $this->binaryPublicKey)) {
            return VerificationResult::mismatch();
        }
        if ($state === 1) {
            return VerificationResult::replay();
        }

        $ttl = max(1, $challenge->expiresAt - $now);
        if (!CacheLock::consumeReserved(
            $cache,
            $stateKey,
            self::lockKey($factorId, $challenge),
            $ttl,
            'AOTP challenge',
        )) {
            return VerificationResult::replay();
        }

        return VerificationResult::success();
    }

    private static function assertAudience(string $audience): void
    {
        if (
            $audience === ''
            || strlen($audience) > 255
            || preg_match('//u', $audience) !== 1
            || preg_match('/[\s\p{Cc}]/u', $audience) === 1
        ) {
            throw new InvalidArgumentException(
                'AOTP audience must be valid UTF-8, contain no whitespace/control characters, and be between 1 and 255 bytes.',
            );
        }
    }

    private static function assertContext(string $context): void
    {
        if (
            $context === ''
            || strlen($context) > 4096
            || preg_match('//u', $context) !== 1
            || preg_match('/\p{Cc}/u', $context) === 1
        ) {
            throw new InvalidArgumentException(
                'AOTP context must be valid UTF-8, contain no control characters, and be between 1 and 4096 bytes.',
            );
        }
    }

    private static function assertFactorId(string $factorId): void
    {
        if ($factorId === '' || strlen($factorId) > self::MAX_FACTOR_ID_LENGTH) {
            throw new InvalidArgumentException('Factor IDs must contain between 1 and 190 bytes.');
        }
    }

    /** @return non-empty-string */
    private static function decodeKey(string $key, int $bytes, string $name): string
    {
        $decoded = Base64Url::decode($key, $name);
        if ($decoded === '' || strlen($decoded) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }

        return $decoded;
    }

    /** @return non-empty-string */
    private static function decodeSignature(string $signature): string
    {
        $decoded = Base64Url::decode($signature, 'AOTP signature');
        if ($decoded === '' || strlen($decoded) !== self::SIGNATURE_BYTES) {
            throw new InvalidArgumentException('AOTP signature has an invalid length.');
        }

        return $decoded;
    }

    private static function encode(string $value): string
    {
        return Base64Url::encode($value);
    }

    private static function lockKey(string $factorId, AotpChallenge $challenge): string
    {
        return hash(
            'sha256',
            "infocyph:otp:aotp:lock:v1\0" . $factorId . "\0" . hash('sha256', $challenge->signingPayload(), true),
        );
    }

    private static function requireSodium(): void
    {
        if (!self::isAvailable()) {
            throw new LogicException('AOTP requires ext-sodium for Ed25519 operations.');
        }
    }

    private static function stateKey(string $factorId, AotpChallenge $challenge): string
    {
        return hash(
            'sha256',
            "infocyph:otp:aotp:state:v1\0" . $factorId . "\0" . hash('sha256', $challenge->signingPayload(), true),
        );
    }
}
