<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Tests\Support\Concurrency;
use Infocyph\OTP\Tests\Support\SqliteAtomicStore;


test('recovery replacement racing consumption commits one serializable final batch', function () {
    $path = tempnam(sys_get_temp_dir(), 'otp-recovery-replace-');
    expect($path)->toBeString();
    $key = str_repeat('r', 32);
    $binding = 'replacement-race-user';
    $oldCode = (new RecoveryCodes(new SqliteAtomicStore($path), $key))
        ->generate($binding, count: 2)
        ->plainCodes[0];

    $results = Concurrency::run(static function (int $worker) use ($path, $key, $binding, $oldCode): int {
        $codes = new RecoveryCodes(new SqliteAtomicStore($path), $key);
        if ($worker === 0) {
            return $codes->consume($binding, $oldCode)->consumed ? 1 : 0;
        }

        $replacement = $codes->generate($binding, count: 3);

        return $replacement->totalGenerated === 3 && $replacement->remainingCount === 3 ? 2 : 250;
    });

    expect($results)->toContain(2);
    $metadata = (new SqliteAtomicStore($path))->metadata($binding);
    expect($metadata['total'])->toBe(3)
        ->and($metadata['remaining'])->toBe(3)
        ->and($metadata['lastUsedAt'])->toBeNull()
        ->and((new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($binding, $oldCode)->consumed)
        ->toBeFalse();

    unlink($path);
});

test('durable recovery isolates full-length factor identifiers during consumption and rotation', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'otp-recovery-owner-');
    if ($path === false) {
        throw new \RuntimeException('Unable to create the recovery database.');
    }

    $key = random_bytes(32);
    $owner = 'otp-recovery-' . hash('sha256', 'owner-a');
    $other = 'otp-recovery-' . hash('sha256', 'owner-b');

    try {
        $proof = (new RecoveryCodes(new SqliteAtomicStore($path), $key))->generate($owner, count: 2)->plainCodes[0];
        $otherProof = (new RecoveryCodes(new SqliteAtomicStore($path), $key))->generate($other, count: 2)->plainCodes[0];

        expect(strlen($owner))->toBe(77)
            ->and((new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($other, $proof)->consumed)->toBeFalse()
            ->and((new SqliteAtomicStore($path))->metadata($other)['remaining'])->toBe(2);

        $results = Concurrency::run(
            static fn(): int => (int) new RecoveryCodes(new SqliteAtomicStore($path), $key)->consume($owner, $proof)->consumed,
            4,
        );
        sort($results);
        expect($results)->toBe([0, 0, 0, 1])
            ->and((new SqliteAtomicStore($path))->metadata($owner)['remaining'])->toBe(1)
            ->and((new SqliteAtomicStore($path))->metadata($other)['lastUsedAt'])->toBeNull();

        $replacement = (new RecoveryCodes(new SqliteAtomicStore($path), $key))->generate($owner, count: 3);
        expect((new SqliteAtomicStore($path))->metadata($owner)['remaining'])->toBe(3)
            ->and((new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($owner, $proof)->consumed)->toBeFalse()
            ->and((new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($owner, $replacement->plainCodes[0])->consumed)->toBeTrue()
            ->and((new SqliteAtomicStore($path))->metadata($other)['remaining'])->toBe(2)
            ->and((new RecoveryCodes(new SqliteAtomicStore($path), $key))->consume($other, $otherProof)->consumed)->toBeTrue()
            ->and((new SqliteAtomicStore($path))->metadata($other)['remaining'])->toBe(1);
    } finally {
        unlink($path);
    }
});
