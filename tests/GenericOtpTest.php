<?php

declare(strict_types=1);

use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Contracts\OtpStoreInterface;
use Infocyph\OTP\Stores\InMemoryOtpStore;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\Tests\Support\SqliteAtomicStore;

test('generic OTP is atomic, single-use, and decrements failed attempts', function () {
    $otp = new GenericOtp(new InMemoryOtpStore(), str_repeat('g', 32), maxAttempts: 3);
    $code = $otp->generate('challenge-1');
    $wrong = str_pad((string) (((int) $code + 1) % 1_000_000), 6, '0', STR_PAD_LEFT);

    expect($otp->verify('challenge-1', $wrong))->toBeFalse()
        ->and($otp->verify('challenge-1', $wrong))->toBeFalse()
        ->and($otp->verify('challenge-1', $wrong))->toBeFalse()
        ->and($otp->verify('challenge-1', $code))->toBeFalse();

    $second = $otp->generate('challenge-2');
    expect($otp->verify('challenge-2', $second))->toBeTrue()
        ->and($otp->verify('challenge-2', $second))->toBeFalse();
});

test('issuing another generic OTP atomically revokes the previous one', function () {
    $otp = new GenericOtp(new InMemoryOtpStore(), str_repeat('g', 32));
    $first = $otp->generate('challenge');
    $second = $otp->generate('challenge');

    expect($otp->verify('challenge', $first))->toBeFalse()
        ->and($otp->verify('challenge', $second))->toBeTrue();
});

test('generic OTP requires safe key and bounded configuration', function () {
    $store = new InMemoryOtpStore();

    expect(fn () => new GenericOtp($store, 'short'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($store, str_repeat('k', 32), digits: 5))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($store, str_repeat('k', 32), ttlSeconds: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($store, str_repeat('k', 32), maxAttempts: 0))->toThrow(InvalidArgumentException::class);
});

test('generic OTP HMAC is bound to challenge and key', function () {
    $store = new InMemoryOtpStore();
    $keyA = new GenericOtp($store, str_repeat('a', 32));
    $keyB = new GenericOtp($store, str_repeat('b', 32));
    $code = $keyA->generate('binding-a');

    expect($keyA->verify('binding-b', $code))->toBeFalse()
        ->and($keyB->verify('binding-a', $code))->toBeFalse()
        ->and($keyA->verify('binding-a', $code))->toBeTrue();
});

test('failed generic OTP attempts never extend absolute expiration', function () {
    $store = new InMemoryOtpStore();
    $store->issue('binding', 'expected-digest', 100, 3);

    expect($store->verifyAndConsume('binding', 'wrong-digest', 99))->toBeFalse()
        ->and($store->verifyAndConsume('binding', 'expected-digest', 100))->toBeFalse();
});

test('generic OTP issue failure never returns a code', function () {
    $store = new class implements OtpStoreInterface {
        /** @var list<array<int|string>> */
        public array $observed = [];

        public function delete(string $storageBinding): bool
        {
            $this->observed[] = [$storageBinding];

            return false;
        }

        public function issue(string $storageBinding, string $digest, int $expiresAt, int $maxAttempts): void
        {
            $this->observed[] = [$storageBinding, $digest, $expiresAt, $maxAttempts];

            throw new RuntimeException('Storage unavailable.');
        }

        public function verifyAndConsume(string $storageBinding, string $candidateDigest, int $now): bool
        {
            $this->observed[] = [$storageBinding, $candidateDigest, $now];

            return false;
        }
    };

    expect(fn () => (new GenericOtp($store, str_repeat('g', 32)))->generate('challenge'))
        ->toThrow(RuntimeException::class, 'Storage unavailable.');
});

test('generic OTP transitions remain atomic across processes', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-generic-');
    expect($path)->toBeString();
    $key = str_repeat('g', 32);
    $binding = 'concurrent-challenge';
    $otp = new GenericOtp(new SqliteAtomicStore($path), $key, maxAttempts: 3);
    $code = $otp->generate($binding);

    $correctResults = Concurrency::run(static function () use ($path, $key, $binding, $code): int {
        $service = new GenericOtp(new SqliteAtomicStore($path), $key, maxAttempts: 3);

        return $service->verify($binding, $code) ? 1 : 0;
    });
    sort($correctResults);
    expect($correctResults)->toBe([0, 1]);

    $code = $otp->generate($binding);
    $wrong = str_pad((string) (((int) $code + 1) % 1_000_000), 6, '0', STR_PAD_LEFT);
    expect(Concurrency::run(static function () use ($path, $key, $binding, $wrong): int {
        $service = new GenericOtp(new SqliteAtomicStore($path), $key, maxAttempts: 3);

        return $service->verify($binding, $wrong) ? 1 : 0;
    }))->toBe([0, 0])
        ->and($otp->verify($binding, $wrong))->toBeFalse()
        ->and($otp->verify($binding, $code))->toBeFalse();

    $old = $otp->generate($binding);
    $newCodePath = $path . '.new-code';
    $race = Concurrency::run(static function (int $worker) use ($path, $key, $binding, $old, $newCodePath): int {
        $service = new GenericOtp(new SqliteAtomicStore($path), $key);
        if ($worker === 0) {
            return $service->verify($binding, $old) ? 1 : 0;
        }

        $newCode = $service->generate($binding);
        file_put_contents($newCodePath, $newCode);

        return 2;
    });
    sort($race);
    expect($race)->toBeIn([[0, 2], [1, 2]]);
    $newCode = file_get_contents($newCodePath);
    expect($newCode)->toBeString()
        ->and($otp->verify($binding, $newCode))->toBeTrue()
        ->and($otp->verify($binding, $newCode))->toBeFalse();

    unlink($newCodePath);
    unlink($path);
});
