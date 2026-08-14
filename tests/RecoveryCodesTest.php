<?php

declare(strict_types=1);

use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\Tests\Support\SqliteAtomicStore;

test('recovery codes are keyed, formatted, atomic, and single use', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));
    $generated = $codes->generate('user-1');
    $first = $codes->consume('user-1', strtolower($generated->plainCodes[0]));
    $second = $codes->consume('user-1', $generated->plainCodes[0]);

    expect($generated->totalGenerated)->toBe(10)
        ->and($generated->remainingCount)->toBe(10)
        ->and($generated->plainCodes)->each->toMatch('/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/')
        ->and($first->consumed)->toBeTrue()
        ->and($first->remainingCount)->toBe(9)
        ->and($second->consumed)->toBeFalse()
        ->and($second->remainingCount)->toBe(9);
});

test('recovery regeneration replaces the entire active batch', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));
    $old = $codes->generate('user-1')->plainCodes[0];
    $new = $codes->generate('user-1')->plainCodes[0];

    expect($codes->consume('user-1', $old)->consumed)->toBeFalse()
        ->and($codes->consume('user-1', $new)->consumed)->toBeTrue();
});

test('recovery code entropy, key, and input are bounded', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));
    $generated = $codes->generate('user-1');

    expect(fn () => new RecoveryCodes(new InMemoryRecoveryCodeStore(), 'short'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $codes->generate('user-1', count: 2, length: 6, characterSet: 'AB'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $codes->generate('user-1', characterSet: 'A'))
        ->toThrow(InvalidArgumentException::class)
        ->and($codes->consume('user-1', str_repeat('A', 513))->consumed)->toBeFalse()
        ->and($codes->consume('user-1', 'invalid!')->consumed)->toBeFalse()
        ->and($codes->consume('user-1', $generated->plainCodes[0])->consumed)->toBeTrue();
});

test('duplicate recovery alphabet characters are normalized before entropy checks', function () {
    $codes = new RecoveryCodes(new InMemoryRecoveryCodeStore(), str_repeat('r', 32));
    $generated = $codes->generate('user-1', count: 2, length: 40, groupSize: 0, characterSet: 'AABB');

    expect($generated->plainCodes)->each->toMatch('/^[AB]{40}$/');
});

test('recovery consume uses mutation state without a fallible metadata follow-up', function () {
    $store = new class implements \Infocyph\OTP\Contracts\RecoveryCodeStoreInterface {
        public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
        {
            expect($binding)->not->toBeEmpty()
                ->and($hashedCode)->not->toBeEmpty();

            return ['consumed' => true, 'total' => 2, 'remaining' => 1, 'lastUsedAt' => $usedAt];
        }

        public function metadata(string $binding): array
        {
            throw new RuntimeException('Metadata must not be queried after consume for ' . $binding . '.');
        }

        public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
        {
            expect($binding)->not->toBeEmpty();

            return ['total' => count($hashedCodes), 'remaining' => count($hashedCodes), 'lastUsedAt' => $issuedAt];
        }
    };
    $result = (new RecoveryCodes($store, str_repeat('r', 32)))->consume('user-1', 'ABCD-EFGH');

    expect($result->consumed)->toBeTrue()
        ->and($result->totalGenerated)->toBe(2)
        ->and($result->remainingCount)->toBe(1);
});

test('same recovery text hashes differently for different bindings', function () {
    $store = new class implements \Infocyph\OTP\Contracts\RecoveryCodeStoreInterface {
        /** @var array<string, string> */
        public array $seen = [];

        public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
        {
            $this->seen[$binding] = $hashedCode;

            return ['consumed' => false, 'total' => 0, 'remaining' => 0, 'lastUsedAt' => $usedAt];
        }

        public function metadata(string $binding): array
        {
            $this->seen[$binding] ??= '';

            return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
        {
            $this->seen[$binding] ??= '';

            return ['total' => count($hashedCodes), 'remaining' => count($hashedCodes), 'lastUsedAt' => $issuedAt];
        }
    };
    $codes = new RecoveryCodes($store, str_repeat('r', 32));
    $codes->consume('user-a', 'ABCD-EFGH-IJKL');
    $codes->consume('user-b', 'ABCD-EFGH-IJKL');

    expect($store->seen['user-a'])->not->toBe($store->seen['user-b']);
});

test('recovery codes reject impossible custom-store consumption state', function (array $state) {
    $store = new class($state) implements \Infocyph\OTP\Contracts\RecoveryCodeStoreInterface {
        public function __construct(private array $state)
        {
        }

        public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
        {
            expect($binding)->toBe('user-1')
                ->and($hashedCode)->toMatch('/^[a-f0-9]{64}$/')
                ->and($usedAt->getTimestamp())->toBeGreaterThan(0);

            return $this->state;
        }

        public function metadata(string $binding): array
        {
            expect($binding)->toBe('user-1');

            return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
        {
            expect($binding)->not->toBeEmpty()
                ->and($hashedCodes)->not->toBeEmpty()
                ->and($issuedAt->getTimestamp())->toBeGreaterThan(0);

            return ['total' => count($hashedCodes), 'remaining' => count($hashedCodes), 'lastUsedAt' => null];
        }
    };

    expect(fn () => (new RecoveryCodes($store, str_repeat('r', 32)))
        ->consume('user-1', 'ABCD-EFGH'))
        ->toThrow(RuntimeException::class);
})->with([
    'consumed is not boolean' => [['consumed' => 1, 'total' => 1, 'remaining' => 0, 'lastUsedAt' => new DateTimeImmutable()]],
    'negative total' => [['consumed' => false, 'total' => -1, 'remaining' => 0, 'lastUsedAt' => null]],
    'negative remaining' => [['consumed' => false, 'total' => 1, 'remaining' => -1, 'lastUsedAt' => null]],
    'remaining exceeds total' => [['consumed' => false, 'total' => 1, 'remaining' => 2, 'lastUsedAt' => null]],
    'last use is wrong type' => [['consumed' => false, 'total' => 1, 'remaining' => 1, 'lastUsedAt' => 'now']],
    'successful consume lacks timestamp' => [['consumed' => true, 'total' => 1, 'remaining' => 0, 'lastUsedAt' => null]],
]);

test('recovery codes reject impossible custom-store replacement state', function (array $state) {
    $store = new class($state) implements \Infocyph\OTP\Contracts\RecoveryCodeStoreInterface {
        public function __construct(private array $state)
        {
        }

        public function consume(string $binding, string $hashedCode, DateTimeImmutable $usedAt): array
        {
            expect($binding)->not->toBeEmpty()
                ->and($hashedCode)->not->toBeEmpty()
                ->and($usedAt->getTimestamp())->toBeGreaterThan(0);

            return ['consumed' => false, 'total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        public function metadata(string $binding): array
        {
            expect($binding)->not->toBeEmpty();

            return ['total' => 0, 'remaining' => 0, 'lastUsedAt' => null];
        }

        public function replace(string $binding, array $hashedCodes, DateTimeImmutable $issuedAt): array
        {
            expect($binding)->toBe('user-1')
                ->and($hashedCodes)->toHaveCount(2)
                ->and($issuedAt->getTimestamp())->toBeGreaterThan(0);

            return $this->state;
        }
    };

    expect(fn () => (new RecoveryCodes($store, str_repeat('r', 32)))->generate('user-1', count: 2))
        ->toThrow(RuntimeException::class, 'invalid replacement state');
})->with([
    'wrong total' => [['total' => 3, 'remaining' => 3, 'lastUsedAt' => null]],
    'wrong remaining' => [['total' => 2, 'remaining' => 1, 'lastUsedAt' => null]],
    'stale last use' => [['total' => 2, 'remaining' => 2, 'lastUsedAt' => new DateTimeImmutable()]],
]);

test('concurrent recovery-code consumption commits exactly one success', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-recovery-');
    expect($path)->toBeString();
    $key = str_repeat('r', 32);
    $binding = 'concurrent-user';
    $code = (new RecoveryCodes(new SqliteAtomicStore($path), $key))
        ->generate($binding, count: 2)
        ->plainCodes[0];

    $results = Concurrency::run(static function () use ($path, $key, $binding, $code): int {
        $result = (new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($binding, $code);

        return $result->consumed ? 1 : 0;
    });
    sort($results);

    expect($results)->toBe([0, 1]);
    unlink($path);
});
