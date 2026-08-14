<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests\Support;

use RuntimeException;
use Throwable;

final class Concurrency
{
    /**
     * Starts workers behind a filesystem barrier and returns their integer results.
     *
     * @param callable(int): int $operation
     * @return list<int>
     */
    public static function run(callable $operation, int $workers = 2): array
    {
        $barrier = tempnam(sys_get_temp_dir(), 'otp-race-');
        if ($barrier === false) {
            throw new RuntimeException('Unable to create the concurrency barrier.');
        }
        $children = [];
        for ($worker = 0; $worker < $workers; $worker++) {
            $processId = pcntl_fork();
            if ($processId === -1) {
                throw new RuntimeException('Unable to fork a concurrency worker.');
            }
            if ($processId === 0) {
                file_put_contents($barrier . '.ready.' . $worker, '1');
                while (!file_exists($barrier . '.go')) {
                    usleep(1_000);
                }
                try {
                    $result = $operation($worker);
                } catch (Throwable $failure) {
                    file_put_contents(
                        $barrier . '.error.' . $worker,
                        $failure::class . ': ' . $failure->getMessage(),
                    );
                    $result = 250;
                }
                file_put_contents($barrier . '.result.' . $worker, (string) max(0, min(255, $result)));
                posix_kill(posix_getpid(), SIGKILL);
            }

            $children[] = $processId;
        }

        $deadline = microtime(true) + 5;
        for ($worker = 0; $worker < $workers; $worker++) {
            while (!file_exists($barrier . '.ready.' . $worker)) {
                if (microtime(true) > $deadline) {
                    throw new RuntimeException('A concurrency worker did not reach the barrier.');
                }
                usleep(1_000);
            }
        }
        file_put_contents($barrier . '.go', '1');

        $results = [];
        $failures = [];
        foreach ($children as $worker => $processId) {
            pcntl_waitpid($processId, $status);
            $result = file_get_contents($barrier . '.result.' . $worker);
            if ($result === false) {
                throw new RuntimeException('A concurrency worker returned no result.');
            }
            $results[] = (int) $result;
            $errorPath = $barrier . '.error.' . $worker;
            if (is_file($errorPath)) {
                $failure = file_get_contents($errorPath);
                $failures[] = sprintf('worker %d: %s', $worker, $failure === false ? 'unknown failure' : $failure);
                unlink($errorPath);
            }
            unlink($barrier . '.ready.' . $worker);
            unlink($barrier . '.result.' . $worker);
        }
        unlink($barrier . '.go');
        unlink($barrier);
        if ($failures !== []) {
            throw new RuntimeException('Concurrency operation failed: ' . implode('; ', $failures));
        }

        return $results;
    }
}
