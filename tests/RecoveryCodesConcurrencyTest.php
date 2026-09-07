<?php

declare(strict_types=1);

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
