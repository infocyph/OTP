<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/** @return array<array-key, mixed> */
function benchmarkResultArray(mixed $value): array
{
    if (!is_array($value)) {
        throw new RuntimeException('Invalid benchmark result structure.');
    }

    return $value;
}

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
        $json = file_get_contents($output);
        if ($json === false) {
            throw new RuntimeException('Missing benchmark output.');
        }
        $document = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        $workloadResult = benchmarkResultArray(benchmarkResultArray(benchmarkResultArray($document)['workloads'] ?? null)[0] ?? null);
        $result = benchmarkResultArray($workloadResult['result'] ?? null);
        $memory = benchmarkResultArray($result['memory'] ?? null);
        $cpu = benchmarkResultArray($result['cpu'] ?? null);
        $metadata = benchmarkResultArray($workloadResult['metadata'] ?? null);

        expect($memory['peak_mb'])->toBeGreaterThan(0)
            ->and($cpu['average_percent'])->toBeGreaterThan(0)
            ->and($result['failed_operations'])->toBe(0);
        if ($workload !== 'cold-start') {
            expect($workloadResult['duration_seconds'])->toBe(3)
                ->and($metadata['duration_per_repetition_seconds'])->toBe(1);
        }
        if ($workload === 'sustained') {
            expect($memory['average_mb'])->toBeGreaterThan(0)
                ->and($memory['growth_mb'])->not->toBeNull()
                ->and($memory['growth_mb'])->toBeGreaterThanOrEqual(0);
        }
    } finally {
        if (is_file($output)) {
            unlink($output);
        }
    }
})->with(['sustained', 'concurrent-verify', 'cold-start']);
