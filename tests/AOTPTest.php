<?php

declare(strict_types=1);

use Infocyph\OTP\AOTP;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\ValueObjects\AotpChallenge;
use Infocyph\OTP\ValueObjects\AotpResponse;
use Infocyph\OTP\VerificationReason;

test('AOTP signs an issued audience-context-bound challenge and consumes it once', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'user-42:aotp:key-v1', 'login:flow-7f2c', now: 1_000);
    $response = AOTP::respond(
        $keys->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-7f2c',
        now: 1_001,
    );

    $first = $aotp->verifyWithResult($cache, 'user-42:aotp:key-v1', $challenge, $response, 1_001);
    $second = $aotp->verifyWithResult($cache, 'user-42:aotp:key-v1', $challenge, $response, 1_002);

    expect($first->matched)->toBeTrue()
        ->and($first->reason)->toBe(VerificationReason::Matched)
        ->and($second->matched)->toBeFalse()
        ->and($second->reason)->toBe(VerificationReason::Replay)
        ->and($second->replayDetected)->toBeTrue();
});

test('AOTP rejects the wrong signer without consuming the challenge', function () {
    $cache = CacheLayerState::memory();
    $correct = AOTP::generateKeyPair();
    $wrong = AOTP::generateKeyPair();
    $aotp = new AOTP($correct->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor', 'login:flow-a', now: 1_000);
    $wrongResponse = AOTP::respond(
        $wrong->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );
    $correctResponse = AOTP::respond(
        $correct->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );

    expect($aotp->verifyWithResult($cache, 'factor', $challenge, $wrongResponse, 1_001)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($aotp->verify($cache, 'factor', $challenge, $correctResponse, 1_002))->toBeTrue();
});

test('AOTP binds issued state to the complete challenge payload', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $issued = $aotp->issue($cache, 'factor', 'transfer:100', now: 1_000);
    $tampered = new AotpChallenge(
        $issued->id,
        $issued->nonce,
        $issued->audience,
        'transfer:100000',
        $issued->issuedAt,
        $issued->expiresAt,
    );
    $tamperedResponse = AOTP::respond(
        $keys->privateKey,
        $tampered,
        'login.example.com',
        'transfer:100000',
        now: 1_001,
    );
    $correctResponse = AOTP::respond(
        $keys->privateKey,
        $issued,
        'login.example.com',
        'transfer:100',
        now: 1_001,
    );

    expect($aotp->verifyWithResult($cache, 'factor', $tampered, $tamperedResponse, 1_001)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($aotp->verify($cache, 'factor', $issued, $correctResponse, 1_002))->toBeTrue();
});

test('AOTP rejects expired, future, and wrong-factor challenges', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor-a', 'login:flow-a', ttlSeconds: 60, now: 1_000);
    $response = AOTP::respond(
        $keys->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );

    expect($aotp->verifyWithResult($cache, 'factor-a', $challenge, $response, 999)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($aotp->verifyWithResult($cache, 'factor-b', $challenge, $response, 1_001)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($aotp->verifyWithResult($cache, 'factor-a', $challenge, $response, 1_060)->reason)
        ->toBe(VerificationReason::Mismatch);
});

test('AOTP client enforces independently expected audience and context before signing', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor', 'login:flow-a', now: 1_000);

    expect(fn () => AOTP::respond(
        $keys->privateKey,
        $challenge,
        'evil.example.com',
        'login:flow-a',
        now: 1_001,
    ))->toThrow(InvalidArgumentException::class, 'audience')
        ->and(fn () => AOTP::respond(
            $keys->privateKey,
            $challenge,
            'login.example.com',
            'transfer:1000',
            now: 1_001,
        ))->toThrow(InvalidArgumentException::class, 'context');
});

test('AOTP client refuses challenges outside their signing lifetime', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor', 'login:flow-a', ttlSeconds: 60, now: 1_000);

    expect(fn () => AOTP::respond(
        $keys->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 999,
    ))->toThrow(InvalidArgumentException::class, 'not currently valid')
        ->and(fn () => AOTP::respond(
            $keys->privateKey,
            $challenge,
            'login.example.com',
            'login:flow-a',
            now: 1_060,
        ))->toThrow(InvalidArgumentException::class, 'not currently valid');
});

test('AOTP does not reveal consumed state to an invalid signer', function () {
    $cache = CacheLayerState::memory();
    $correct = AOTP::generateKeyPair();
    $wrong = AOTP::generateKeyPair();
    $aotp = new AOTP($correct->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor', 'login:flow-a', now: 1_000);
    $correctResponse = AOTP::respond(
        $correct->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );
    $wrongResponse = AOTP::respond(
        $wrong->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );

    expect($aotp->verifyWithResult($cache, 'factor', $challenge, $correctResponse, 1_001)->matched)
        ->toBeTrue()
        ->and($aotp->verifyWithResult($cache, 'factor', $challenge, $wrongResponse, 1_002)->reason)
        ->toBe(VerificationReason::Mismatch)
        ->and($aotp->verifyWithResult($cache, 'factor', $challenge, $correctResponse, 1_002)->reason)
        ->toBe(VerificationReason::Replay);
});

test('AOTP payloads round-trip and redact sensitive debug state', function () {
    $cache = CacheLayerState::memory();
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue($cache, 'factor', 'transaction', now: 1_000);
    $response = AOTP::respond(
        $keys->privateKey,
        $challenge,
        'login.example.com',
        'transaction',
        now: 1_001,
    );
    $parsedChallenge = AotpChallenge::fromArray($challenge->toArray());
    $parsedResponse = AotpResponse::fromArray($response->toArray());

    expect($parsedChallenge->signingPayload())->toBe($challenge->signingPayload())
        ->and($parsedResponse->signature)->toBe($response->signature)
        ->and($keys->__debugInfo()['privateKey'])->toBe('[redacted]')
        ->and($challenge->__debugInfo()['nonce'])->toBe('[redacted]')
        ->and($challenge->__debugInfo()['context'])->toBe('[redacted]')
        ->and($response->__debugInfo()['signature'])->toBe('[redacted]');
});

test('AOTP validates key and challenge configuration bounds', function () {
    $keys = AOTP::generateKeyPair();
    $cache = CacheLayerState::memory();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');

    expect(fn () => new AOTP('bad', 'login.example.com'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new AOTP($keys->publicKey, ''))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new AOTP($keys->publicKey, "login\n.example.com"))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $aotp->issue($cache, '', 'login', now: 1_000))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $aotp->issue($cache, 'factor', '', now: 1_000))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $aotp->issue($cache, 'factor', "login\nflow", now: 1_000))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $aotp->issue($cache, 'factor', 'login', ttlSeconds: 0, now: 1_000))
        ->toThrow(InvalidArgumentException::class);
});

test('AOTP concurrent verification accepts exactly one request', function () {
    if (!extension_loaded('pcntl') || !extension_loaded('posix') || !extension_loaded('pdo_sqlite')) {
        $this->markTestSkipped('pcntl, posix, and pdo_sqlite are required.');
    }

    $path = tempnam(sys_get_temp_dir(), 'otp-aotp-');
    if ($path === false) {
        throw new RuntimeException('Unable to create AOTP concurrency database.');
    }
    $keys = AOTP::generateKeyPair();
    $aotp = new AOTP($keys->publicKey, 'login.example.com');
    $challenge = $aotp->issue(CacheLayerState::sqlite($path), 'factor', 'login:flow-a', now: 1_000);
    $response = AOTP::respond(
        $keys->privateKey,
        $challenge,
        'login.example.com',
        'login:flow-a',
        now: 1_001,
    );

    $results = Concurrency::run(static function () use ($path, $keys, $challenge, $response): int {
        $service = new AOTP($keys->publicKey, 'login.example.com');

        return $service->verify(CacheLayerState::sqlite($path), 'factor', $challenge, $response, 1_001) ? 1 : 0;
    });

    unlink($path);
    expect(array_sum($results))->toBe(1);
});
