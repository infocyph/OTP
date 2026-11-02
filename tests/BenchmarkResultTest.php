<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

test('benchmark results retain measured memory and CPU for acceptance budgets', function (string $workload) {
    $root = dirname(__DIR__);
    $output = sys_get_temp_dir() . '/otp-benchmark-contract-' . bin2hex(random_bytes(8)) . '.json';

    try {
        $process = new Process([
            PHP_BINARY,
            $root . '/benchmarks/release-gate.php',
            '--autoload=' . $root . '/vendor/autoload.php',
            '--output=' . $output,
            '--release=test',
            '--duration=1',
            '--repetitions=3',
            '--workload=' . $workload,
        ], $root);
        $process->mustRun();
        $document = json_decode(file_get_contents($output), true, flags: JSON_THROW_ON_ERROR);
        $result = $document['workloads'][0]['result'];

        expect($result['memory']['peak_mb'])->toBeGreaterThan(0)
            ->and($result['cpu']['average_percent'])->toBeGreaterThan(0)
            ->and($result['failed_operations'])->toBe(0);
        if ($workload === 'sustained') {
            expect($result['memory']['average_mb'])->toBeGreaterThan(0)
                ->and($result['memory']['growth_mb'])->not->toBeNull()
                ->and($result['memory']['growth_mb'])->toBeGreaterThanOrEqual(0);
        }
    } finally {
        if (is_file($output)) {
            unlink($output);
        }
    }
})->with(['sustained', 'concurrent-verify', 'cold-start']);
