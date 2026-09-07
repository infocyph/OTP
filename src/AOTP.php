<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\AotpChallenge;
use Infocyph\OTP\ValueObjects\AotpKeyPair;
use Infocyph\OTP\ValueObjects\AotpResponse;
use InvalidArgumentException;
use RuntimeException;

final readonly class AOTP
{
    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_TTL_SECONDS = 600;

    private const int RESERVATION_ATTEMPTS = 4;

    /** @var non-empty-string */
    private string $binaryPublicKey;

    public function __construct(
        string $publicKey,
        private string $audience,
    ) {
        $this->binaryPublicKey = self::decodeKey($publicKey, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'AOTP public key');
        self::assertAudience($audience);
    }

    public static function generateKeyPair(): AotpKeyPair
    {
        $pair = sodium_crypto_sign_keypair();

        return new AotpKeyPair(
            self::encode(sodium_crypto_sign_publickey($pair)),
            self::encode(sodium_crypto_sign_secretkey($pair)),
        );
    }

    public static function respond(
        #[\SensitiveParameter]
        string $privateKey,
        AotpChallenge $challenge,
        string $expectedAudience,
    ): AotpResponse {
        self::assertAudience($expectedAudience);
        if (!hash_equals($expectedAudience, $challenge->audience)) {
            throw new InvalidArgumentException('AOTP challenge audience does not match the expected verifier.');
        }
        $binaryPrivateKey = self::decodeKey(
            $privateKey,
            SODIUM_CRYPTO_SIGN_SECRETKEYBYTES,
            'AOTP private key',
        );
        $signature = sodium_crypto_sign_detached($challenge->signingPayload(), $binaryPrivateKey);

        return new AotpResponse($challenge->id, self::encode($signature));
    }

    public function issue(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        string $context = '',
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
        if ($state === 1) {
            return VerificationResult::replay();
        }

        $signature = self::decodeSignature($response->signature);
        if (!sodium_crypto_sign_verify_detached($signature, $challenge->signingPayload(), $this->binaryPublicKey)) {
            return VerificationResult::mismatch();
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
        if ($audience === '' || strlen($audience) > 255 || preg_match('//u', $audience) !== 1) {
            throw new InvalidArgumentException('AOTP audience must be valid UTF-8 between 1 and 255 bytes.');
        }
    }

    private static function assertContext(string $context): void
    {
        if (strlen($context) > 4096 || preg_match('//u', $context) !== 1) {
            throw new InvalidArgumentException('AOTP context must be valid UTF-8 and no longer than 4096 bytes.');
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
        try {
            $decoded = sodium_base642bin($key, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new InvalidArgumentException($name . ' must be valid URL-safe Base64 without padding.');
        }
        if (strlen($decoded) !== $bytes) {
            throw new InvalidArgumentException($name . ' has an invalid length.');
        }

        return $decoded;
    }

    /** @return non-empty-string */
    private static function decodeSignature(string $signature): string
    {
        try {
            $decoded = sodium_base642bin($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            throw new InvalidArgumentException('AOTP signature must be valid URL-safe Base64 without padding.');
        }
        if (strlen($decoded) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new InvalidArgumentException('AOTP signature has an invalid length.');
        }

        return $decoded;
    }

    private static function encode(string $value): string
    {
        return sodium_bin2base64($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    private static function lockKey(string $factorId, AotpChallenge $challenge): string
    {
        return hash(
            'sha256',
            "infocyph:otp:aotp:lock:v1\0" . $factorId . "\0" . hash('sha256', $challenge->signingPayload(), true),
        );
    }

    private static function stateKey(string $factorId, AotpChallenge $challenge): string
    {
        return hash(
            'sha256',
            "infocyph:otp:aotp:state:v1\0" . $factorId . "\0" . hash('sha256', $challenge->signingPayload(), true),
        );
    }
}
