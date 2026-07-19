<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\OTP\Contracts\AtomicReplayStoreInterface;
use Infocyph\OTP\Contracts\ReplayStoreInterface;

final class ReplayProtection
{
    public static function advance(
        ReplayStoreInterface $store,
        string $namespace,
        string $binding,
        int $value,
    ): bool {
        if ($store instanceof AtomicReplayStoreInterface) {
            return $store->advance($namespace, $binding, $value);
        }

        $current = $store->getState($namespace, $binding);
        if (is_int($current) && $value <= $current) {
            return false;
        }

        $store->setState($namespace, $binding, $value);

        return true;
    }
}
