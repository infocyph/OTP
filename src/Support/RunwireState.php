<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use LogicException;

/** @internal */
final class RunwireState
{
    public static function acquireLock(
        LockProviderInterface $locks,
        string $key,
        ?RunwireExecutionContext $runwire,
        float $waitSeconds,
        float $leaseSeconds,
    ): ?LockHandle {
        self::checkpoint($runwire);
        if (
            $runwire === null
            || $runwire->scope === null
            || !$runwire->runtime->capabilities->supportsRunwireCoroutines
        ) {
            return $locks->acquire($key, $waitSeconds, $leaseSeconds);
        }

        $waitSeconds = self::remainingWaitSeconds($runwire, $waitSeconds);
        if ($waitSeconds <= 0.0) {
            self::checkpoint($runwire);

            return null;
        }

        $deadline = (int) hrtime(true) + (int) ceil($waitSeconds * 1_000_000_000);
        do {
            self::checkpoint($runwire);
            $handle = $locks->acquire($key, 0.0, $leaseSeconds);
            if ($handle !== null) {
                return $handle;
            }

            $remainingNanoseconds = $deadline - (int) hrtime(true);
            if ($remainingNanoseconds <= 0) {
                self::checkpoint($runwire);

                return null;
            }

            $runwire->scope->sleep(min(0.005, $remainingNanoseconds / 1_000_000_000));
        } while (true);
    }

    public static function checkpoint(?RunwireExecutionContext $runwire): void
    {
        if ($runwire === null) {
            return;
        }

        self::validate($runwire);
        $runwire->request?->cancellation->throwIfCancelled();
        $runwire->scope?->cancellation()->throwIfCancelled();
    }

    private static function remainingWaitSeconds(RunwireExecutionContext $runwire, float $waitSeconds): float
    {
        $remaining = $waitSeconds;
        $requestRemaining = $runwire->request?->deadline()->remainingSeconds();
        if ($requestRemaining !== null) {
            $remaining = min($remaining, $requestRemaining);
        }
        $scopeRemaining = $runwire->scope?->cancellation()->deadline()->remainingSeconds();
        if ($scopeRemaining !== null) {
            $remaining = min($remaining, $scopeRemaining);
        }

        return max(0.0, $remaining);
    }

    private static function validate(RunwireExecutionContext $runwire): void
    {
        $request = $runwire->request;
        if ($request !== null) {
            if ($request->completed()) {
                throw new LogicException('Completed Runwire request context cannot be used for OTP state operations.');
            }
            if ($request->runtime() !== $runwire->runtime) {
                throw new LogicException('Runwire request context is bound to a different runtime context.');
            }
        }

        $pid = getmypid();
        if (is_int($pid) && $runwire->runtime->pid !== 0 && $runwire->runtime->pid !== $pid) {
            throw new LogicException('Runwire runtime context belongs to a different process.');
        }
    }
}
