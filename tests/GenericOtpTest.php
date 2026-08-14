<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Adapter\ArrayCacheAdapter;
use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\OTP\Tests\Support\Concurrency;

test('generic OTP is atomic, single-use, and decrements failed attempts', function () {
    $cache = CacheLayerState::memory();
    $otp = new GenericOtp($cache, str_repeat('g', 32), maxAttempts: 3);
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
    $cache = CacheLayerState::memory();
    $otp = new GenericOtp($cache, str_repeat('g', 32));
    $first = $otp->generate('challenge');
    $second = $otp->generate('challenge');

    expect($otp->verify('challenge', $first))->toBeFalse()
        ->and($otp->verify('challenge', $second))->toBeTrue();
});

test('generic OTP requires safe key and bounded configuration', function () {
    $cache = CacheLayerState::memory();

    expect(fn () => new GenericOtp($cache, 'short'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($cache, str_repeat('k', 32), digits: 5))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($cache, str_repeat('k', 32), ttlSeconds: 0))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GenericOtp($cache, str_repeat('k', 32), maxAttempts: 0))
        ->toThrow(InvalidArgumentException::class);
});

test('authentication state policy rejects unsafe CacheLayer configurations', function () {
    $key = str_repeat('g', 32);
    $integrityKey = str_repeat('i', 32);

    expect(fn () => new GenericOtp(
        Cache::memory('fail-open', new CacheOptions(integrityKey: $integrityKey)),
        $key,
    ))->toThrow(InvalidArgumentException::class, 'fail-closed')
        ->and(fn () => new GenericOtp(
            Cache::memory('unsigned', new CacheOptions(failOpen: false)),
            $key,
        ))->toThrow(InvalidArgumentException::class, 'payload integrity')
        ->and(fn () => new GenericOtp(
            Cache::tiered(
                [new ArrayCacheAdapter('tiered-state')],
                options: new CacheOptions(integrityKey: $integrityKey, failOpen: false),
            ),
            $key,
        ))->toThrow(InvalidArgumentException::class, 'authoritative direct backend')
        ->and(fn () => new GenericOtp(
            new Cache(
                new ArrayCacheAdapter('no-lock'),
                options: new CacheOptions(integrityKey: $integrityKey, failOpen: false),
            ),
            $key,
        ))->toThrow(InvalidArgumentException::class, 'coordinated lock capability')
        ->and(new GenericOtp(CacheLayerState::memory(), $key))->toBeInstanceOf(GenericOtp::class);
});

test('generic OTP HMAC is bound to challenge and key', function () {
    $cache = CacheLayerState::memory();
    $keyA = new GenericOtp($cache, str_repeat('a', 32));
    $keyB = new GenericOtp($cache, str_repeat('b', 32));
    $code = $keyA->generate('binding-a');

    expect($keyA->verify('binding-b', $code))->toBeFalse()
        ->and($keyB->verify('binding-a', $code))->toBeFalse()
        ->and($keyA->verify('binding-a', $code))->toBeTrue();
});

test('malformed generic OTP input does not consume an attempt', function () {
    $cache = CacheLayerState::memory();
    $otp = new GenericOtp($cache, str_repeat('g', 32), maxAttempts: 1);
    $code = $otp->generate('challenge');

    expect($otp->verify('challenge', 'bad'))->toBeFalse()
        ->and($otp->verify('challenge', $code))->toBeTrue();
});

test('failed generic OTP attempts never extend absolute expiration', function () {
    $key = str_repeat('g', 32);
    $expiresAt = time() + 60;
    $cache = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $cache->method('get')->willReturn([
        'v' => 1,
        'digest' => hash_hmac('sha256', "generic-otp\0" . 'challenge' . "\0" . '123456', $key),
        'remainingAttempts' => 3,
        'expiresAt' => $expiresAt,
    ]);
    $cache->expects($this->once())->method('set')->with(
        $this->callback(static fn (string $cacheKey): bool => strlen($cacheKey) === 64),
        $this->callback(static fn (array $state): bool => $state['expiresAt'] === $expiresAt),
        $this->callback(static fn (int $ttl): bool => $ttl > 0 && $ttl <= 60),
    )->willReturn(true);

    $otp = new GenericOtp($cache, $key);
    expect($otp->verify('challenge', '654321'))->toBeFalse();
});

test('generic OTP cache failure never returns a code', function () {
    $handle = new LockHandle('lock', 'token');
    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->once())->method('acquire')->willReturn($handle);
    $locks->expects($this->once())->method('refresh')->with($handle, 30.0)->willReturn(true);
    $locks->expects($this->once())->method('release')->with($handle);
    $cache = CacheLayerState::configureMock(
        $this->createMock(AuthenticationStateCacheInterface::class),
        $locks,
    );
    $cache->expects($this->once())->method('set')->willReturn(false);

    expect(fn () => (new GenericOtp($cache, str_repeat('g', 32)))->generate('challenge'))
        ->toThrow(RuntimeException::class, 'Unable to store generic OTP state.');
});

test('lock release cleanup preserves failures and committed results', function () {
    $handle = new LockHandle('lock', 'token');
    $locks = $this->createMock(LockProviderInterface::class);
    $locks->method('acquire')->willReturn($handle);
    $locks->method('refresh')->willReturn(true);
    $locks->method('release')->willThrowException(new RuntimeException('Release failed.'));

    $readFailure = CacheLayerState::configureMock(
        $this->createMock(AuthenticationStateCacheInterface::class),
        $locks,
    );
    $readFailure->method('get')->willThrowException(new RuntimeException('Primary read failed.'));
    expect(fn () => (new GenericOtp($readFailure, str_repeat('g', 32)))->verify('binding', '123456'))
        ->toThrow(RuntimeException::class, 'Primary read failed.');

    $committed = CacheLayerState::configureMock(
        $this->createMock(AuthenticationStateCacheInterface::class),
        $locks,
    );
    $committed->expects($this->once())->method('set')->willReturn(true);
    expect((new GenericOtp($committed, str_repeat('g', 32)))->generate('binding'))
        ->toMatch('/^\d{6}$/');
});

test('generic OTP validity begins after lock acquisition', function () {
    $locks = new class implements LockProviderInterface {
        private int $acquisitions = 0;

        public function acquire(string $key, float $waitSeconds, float $leaseSeconds = 30.0): ?LockHandle
        {
            if ($waitSeconds <= 0 || $leaseSeconds <= 0) {
                return null;
            }
            if ($this->acquisitions++ === 0) {
                usleep(1_100_000);
            }

            return new LockHandle($key, 'delayed');
        }

        public function refresh(?LockHandle $handle, float $leaseSeconds): bool
        {
            return $handle !== null && $handle->token !== '' && $leaseSeconds > 0;
        }

        public function release(?LockHandle $handle): void
        {
        }
    };
    $cache = Cache::memory(
        'delayed-issuance',
        new CacheOptions(integrityKey: str_repeat('i', 32), failOpen: false),
    )->setLockProvider($locks);
    $service = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 1);
    $code = $service->generate('binding');

    expect($service->verify('binding', $code))->toBeTrue();
});

test('generic OTP rejects impossible cached state', function (array $state) {
    $cache = CacheLayerState::memory();
    $cache->set(hash('sha256', "infocyph:otp:generic:state:v1\0binding"), $state, 60);

    expect(fn () => (new GenericOtp($cache, str_repeat('g', 32), maxAttempts: 3))
        ->verify('binding', '123456'))
        ->toThrow(RuntimeException::class, 'Invalid generic OTP state');
})->with([
    'uppercase digest' => [[
        'v' => 1,
        'digest' => str_repeat('A', 64),
        'remainingAttempts' => 1,
        'expiresAt' => 100,
    ]],
    'inflated remaining attempts' => [[
        'v' => 1,
        'digest' => str_repeat('a', 64),
        'remainingAttempts' => 4,
        'expiresAt' => 100,
    ]],
    'extra structure' => [[
        'v' => 1,
        'digest' => str_repeat('a', 64),
        'remainingAttempts' => 1,
        'expiresAt' => 100,
        'extra' => true,
    ]],
    'invalid timestamp' => [[
        'v' => 1,
        'digest' => str_repeat('a', 64),
        'remainingAttempts' => 1,
        'expiresAt' => -1,
    ]],
]);

test('generic OTP read and successful-consumption delete failures fail closed', function () {
    $readFailure = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $readFailure->expects($this->once())
        ->method('get')
        ->willThrowException(new RuntimeException('Backend unavailable.'));
    $service = new GenericOtp($readFailure, str_repeat('g', 32));
    expect(fn () => $service->verify('challenge', '123456'))
        ->toThrow(RuntimeException::class, 'Backend unavailable.');

    $key = str_repeat('g', 32);
    $deleteFailure = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $deleteFailure->method('get')->willReturn([
        'v' => 1,
        'digest' => hash_hmac('sha256', "generic-otp\0" . 'challenge' . "\0" . '123456', $key),
        'remainingAttempts' => 3,
        'expiresAt' => time() + 60,
    ]);
    $deleteFailure->expects($this->once())->method('delete')->willReturn(false);
    $service = new GenericOtp($deleteFailure, $key);
    expect(fn () => $service->verify('challenge', '123456'))
        ->toThrow(RuntimeException::class, 'Unable to delete generic OTP state.');
});

test('generic OTP deletion is scoped and expired records are rejected', function () {
    $cache = CacheLayerState::memory();
    $service = new GenericOtp($cache, str_repeat('g', 32));
    $code = $service->generate('cancelled');

    expect($service->delete('cancelled'))->toBeTrue()
        ->and($service->verify('cancelled', $code))->toBeFalse();

    $expired = CacheLayerState::configureMock($this->createMock(AuthenticationStateCacheInterface::class));
    $expired->method('get')->willReturn([
        'v' => 1,
        'digest' => str_repeat('a', 64),
        'remainingAttempts' => 1,
        'expiresAt' => time() - 1,
    ]);
    $expired->expects($this->once())->method('delete')->willReturn(true);
    expect((new GenericOtp($expired, str_repeat('g', 32)))
        ->verify('expired', '123456'))->toBeFalse();
});

test('generic OTP fails closed when its state lock cannot be acquired', function () {
    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->once())->method('acquire')->willReturn(null);
    $cache = CacheLayerState::configureMock(
        $this->createMock(AuthenticationStateCacheInterface::class),
        $locks,
    );

    expect(fn () => (new GenericOtp($cache, str_repeat('g', 32)))->generate('challenge'))
        ->toThrow(RuntimeException::class, 'Unable to acquire the OTP state lock.');
});

test('generic OTP does not mutate after lock ownership is lost', function () {
    $handle = new LockHandle('lock', 'token');
    $locks = $this->createMock(LockProviderInterface::class);
    $locks->method('acquire')->willReturn($handle);
    $locks->expects($this->once())->method('refresh')->willReturn(false);
    $locks->expects($this->once())->method('release')->with($handle);
    $cache = CacheLayerState::configureMock(
        $this->createMock(AuthenticationStateCacheInterface::class),
        $locks,
    );
    $cache->expects($this->never())->method('set');

    expect(fn () => (new GenericOtp($cache, str_repeat('g', 32)))->generate('challenge'))
        ->toThrow(RuntimeException::class, 'The OTP state lock was lost before mutation.');
});

test('generic OTP transitions remain atomic across processes', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-generic-');
    expect($path)->toBeString();
    $key = str_repeat('g', 32);
    $binding = 'concurrent-challenge';
    $cache = CacheLayerState::sqlite($path);
    $otp = new GenericOtp($cache, $key, maxAttempts: 3);
    $code = $otp->generate($binding);

    $correctResults = Concurrency::run(static function () use ($path, $key, $binding, $code): int {
        $cache = CacheLayerState::sqlite($path);
        $service = new GenericOtp($cache, $key, maxAttempts: 3);

        return $service->verify($binding, $code) ? 1 : 0;
    });
    sort($correctResults);
    expect($correctResults)->toBe([0, 1]);

    $code = $otp->generate($binding);
    $wrong = str_pad((string) (((int) $code + 1) % 1_000_000), 6, '0', STR_PAD_LEFT);
    expect(Concurrency::run(static function () use ($path, $key, $binding, $wrong): int {
        $cache = CacheLayerState::sqlite($path);
        $service = new GenericOtp($cache, $key, maxAttempts: 3);

        return $service->verify($binding, $wrong) ? 1 : 0;
    }))->toBe([0, 0])
        ->and($otp->verify($binding, $wrong))->toBeFalse()
        ->and($otp->verify($binding, $code))->toBeFalse();

    $old = $otp->generate($binding);
    $newCodePath = $path . '.new-code';
    $race = Concurrency::run(static function (int $worker) use ($path, $key, $binding, $old, $newCodePath): int {
        $cache = CacheLayerState::sqlite($path);
        $service = new GenericOtp($cache, $key);
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
