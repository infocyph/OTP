<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;

const COLD_START_OPERATIONS = 30;
const COLD_START_STABILITY_SPREAD_PERCENT = 10.0;
const DEFAULT_DURATION_SECONDS = 8.0;
const DEFAULT_REPETITIONS = 3;
const MAX_MEMORY_GROWTH_MB = 8.0;
const MAX_P99_LATENCY_MS = 1.0;
const MAX_PEAK_MEMORY_MB = 64.0;
const STABILITY_SPREAD_PERCENT = 3.0;
const WARMUP_OPERATIONS = 5_000;

$options = getopt('', [
    'autoload:',
    'duration::',
    'output:',
    'release:',
    'repetitions::',
    'stable',
    'workload::',
]);

$autoload = $options['autoload'] ?? null;
$output = $options['output'] ?? null;
$release = $options['release'] ?? null;
$duration = isset($options['duration']) ? (float) $options['duration'] : DEFAULT_DURATION_SECONDS;
$repetitions = isset($options['repetitions']) ? (int) $options['repetitions'] : DEFAULT_REPETITIONS;
$stableEnvironment = array_key_exists('stable', $options);
$workloadName = $options['workload'] ?? 'sustained';

if (!is_string($autoload) || $autoload === '' || !is_file($autoload)) {
    throw new RuntimeException('A readable --autoload path is required.');
}
if (!is_string($output) || $output === '') {
    throw new RuntimeException('A non-empty --output path is required.');
}
if (!is_string($release) || $release === '') {
    throw new RuntimeException('A non-empty --release identifier is required.');
}
if ($duration < 1.0 || $duration > 60.0) {
    throw new RuntimeException('--duration must be between 1 and 60 seconds.');
}
if ($repetitions < 3 || $repetitions > 10) {
    throw new RuntimeException('--repetitions must be between 3 and 10.');
}
if (!in_array($workloadName, ['cold-start', 'sustained'], true)) {
    throw new RuntimeException('--workload must be either cold-start or sustained.');
}

require $autoload;

$workload = $workloadName === 'cold-start'
    ? runColdStartWorkload($autoload, $repetitions)
    : runSustainedWorkload($duration, $repetitions);
$environmentStable = $stableEnvironment
    && ($workload['result']['stability']['status'] ?? null) === 'stable';
$document = [
    'schema_version' => 1,
    'generated_at' => gmdate('c'),
    'environment' => environment($environmentStable, $release),
    'workloads' => [$workload],
];

$directory = dirname($output);
if (!is_dir($directory) && !mkdir($directory, 0777, true) && !is_dir($directory)) {
    throw new RuntimeException('Unable to create benchmark output directory.');
}
$json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
if (file_put_contents($output, $json . PHP_EOL) === false) {
    throw new RuntimeException('Unable to write benchmark result.');
}

printf(
    "%s benchmark: %.2f successful RPM, %.2f%% spread, %s environment\n",
    $workloadName === 'cold-start' ? 'Cold-start' : 'Sustained',
    $workload['result']['successful_rpm'],
    $workload['result']['stability']['spread_percent'],
    $environmentStable ? 'stable' : 'unverified',
);

/**
 * @return array<string, mixed>
 */
function environment(bool $stable, string $release): array
{
    $extensions = get_loaded_extensions();
    sort($extensions);
    $cpuModel = cpuModel();
    $operatingSystem = php_uname('s') . ' ' . php_uname('r');
    $opcache = filter_var(ini_get('opcache.enable_cli'), FILTER_VALIDATE_BOOL);
    $jit = trim((string) ini_get('opcache.jit'));
    $xdebug = extension_loaded('xdebug');
    $runner = getenv('OTP_BENCHMARK_RUNNER') ?: 'local-cli';
    $fingerprint = getenv('OTP_BENCHMARK_FINGERPRINT');

    if (!is_string($fingerprint) || $fingerprint === '') {
        $fingerprint = hash('sha256', implode('|', [
            PHP_VERSION,
            PHP_SAPI,
            $operatingSystem,
            $cpuModel,
            (string) ini_get('memory_limit'),
            $opcache ? 'opcache-on' : 'opcache-off',
            $jit === '' ? 'jit-off' : $jit,
            $xdebug ? 'xdebug-on' : 'xdebug-off',
            implode(',', $extensions),
            $runner,
        ]));
    }

    return [
        'stable' => $stable,
        'fingerprint' => $fingerprint,
        'php_version' => PHP_VERSION,
        'php_sapi' => PHP_SAPI,
        'operating_system' => $operatingSystem,
        'cpu_model' => $cpuModel,
        'memory_limit' => (string) ini_get('memory_limit'),
        'opcache' => $opcache,
        'jit' => $jit === '' ? false : $jit,
        'xdebug' => $xdebug,
        'extensions' => $extensions,
        'runner' => $runner,
        'release' => $release,
    ];
}

function cpuModel(): string
{
    $contents = is_readable('/proc/cpuinfo')
        ? file_get_contents('/proc/cpuinfo')
        : false;
    if (is_string($contents) && preg_match('/^model name\s*:\s*(.+)$/m', $contents, $match) === 1) {
        return trim($match[1]);
    }

    return php_uname('m');
}

function cpuSeconds(array $usage): float
{
    return ((int) ($usage['ru_utime.tv_sec'] ?? 0))
        + ((int) ($usage['ru_utime.tv_usec'] ?? 0)) / 1_000_000
        + ((int) ($usage['ru_stime.tv_sec'] ?? 0))
        + ((int) ($usage['ru_stime.tv_usec'] ?? 0)) / 1_000_000;
}

/**
 * @param list<float> $values
 */
function median(array $values): float
{
    sort($values);
    $count = count($values);
    $middle = intdiv($count, 2);

    return $count % 2 === 1
        ? $values[$middle]
        : ($values[$middle - 1] + $values[$middle]) / 2;
}

/**
 * @param list<float> $values
 */
function percentile(array $values, float $percentile): ?float
{
    if ($values === []) {
        return null;
    }

    sort($values);
    $index = (int) ceil(($percentile / 100) * count($values)) - 1;

    return $values[max(0, min(count($values) - 1, $index))];
}

/**
 * @param array<string, mixed> $metadata
 * @param list<float> $rpms
 * @param list<float> $latencies
 * @param array{average_percent:?float,peak_percent:?float} $cpu
 * @param array{average_mb:?float,peak_mb:?float,growth_mb:?float} $memory
 * @return array<string, mixed>
 */
function buildWorkloadResult(
    string $name,
    string $type,
    array $metadata,
    int $repetitions,
    int $warmupOperations,
    float $durationSeconds,
    int $attempted,
    int $successful,
    int $failed,
    array $rpms,
    array $latencies,
    array $cpu,
    array $memory,
    float $stabilityLimit,
    string $unstableStatus,
): array {
    $rpmMedian = median($rpms);
    $spread = $rpmMedian > 0.0
        ? ((max($rpms) - min($rpms)) / $rpmMedian) * 100
        : 100.0;

    return [
        'name' => $name,
        'type' => $type,
        'metadata' => $metadata,
        'repetitions' => $repetitions,
        'warmup_operations' => $warmupOperations,
        'duration_seconds' => $durationSeconds,
        'concurrency' => 1,
        'result' => [
            'attempted_operations' => $attempted,
            'successful_operations' => $successful,
            'failed_operations' => $failed,
            'timeouts' => 0,
            'successful_rpm' => round($rpmMedian, 5),
            'error_rate' => $attempted === 0 ? 0.0 : $failed / $attempted,
            'latency_ms' => [
                'minimum' => $latencies === [] ? null : min($latencies),
                'average' => $latencies === [] ? null : array_sum($latencies) / count($latencies),
                'p50' => percentile($latencies, 50),
                'p95' => percentile($latencies, 95),
                'p99' => percentile($latencies, 99),
                'maximum' => $latencies === [] ? null : max($latencies),
            ],
            'cpu' => $cpu,
            'memory' => $memory,
            'stability' => [
                'status' => $spread <= $stabilityLimit ? 'stable' : $unstableStatus,
                'spread_percent' => round($spread, 5),
            ],
        ],
    ];
}

/**
 * @return array<string, mixed>
 */
function runSustainedWorkload(float $duration, int $repetitions): array
{
    $rpms = [];
    $latencies = [];
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $cpuSeconds = 0.0;
    $wallSeconds = 0.0;
    $memoryStarts = [];
    $memoryEnds = [];
    $memoryPeaks = [];

    for ($repetition = 0; $repetition < $repetitions; $repetition++) {
        $cache = Cache::memory(
            'otp-release-gate-' . $repetition,
            new CacheOptions(
                integrityKey: str_repeat('i', 32),
                allowClosures: false,
                allowObjects: false,
                failOpen: false,
            ),
        );
        $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
        $operation = static function () use ($otp): void {
            $code = $otp->generate('release-gate');

            if (strlen($code) !== 6 || !ctype_digit($code)) {
                throw new RuntimeException('Generic OTP benchmark produced an invalid code.');
            }
        };

        for ($index = 0; $index < WARMUP_OPERATIONS; $index++) {
            $operation();
        }

        $usageBefore = getrusage();
        $memoryStart = memory_get_usage(true);
        $start = hrtime(true);
        $deadline = $start + (int) round($duration * 1_000_000_000);
        $repSuccessful = 0;

        while (true) {
            $before = hrtime(true);
            if ($before >= $deadline) {
                break;
            }

            try {
                $operation();
                $repSuccessful++;
                $successful++;
            } catch (Throwable) {
                $failed++;
            }
            $attempted++;

            $after = hrtime(true);
            if ($attempted % 100 === 0) {
                $latencies[] = ($after - $before) / 1_000_000;
            }
        }

        $end = hrtime(true);
        $usageAfter = getrusage();
        $elapsed = ($end - $start) / 1_000_000_000;
        $wallSeconds += $elapsed;
        $cpuSeconds += max(0.0, cpuSeconds($usageAfter) - cpuSeconds($usageBefore));
        $memoryStarts[] = $memoryStart / 1_048_576;
        $memoryEnds[] = memory_get_usage(true) / 1_048_576;
        $memoryPeaks[] = memory_get_peak_usage(true) / 1_048_576;
        $rpms[] = $elapsed > 0.0 ? ($repSuccessful / $elapsed) * 60 : 0.0;
    }

    if ($failed !== 0) {
        throw new RuntimeException('Representative benchmark recorded failed operations.');
    }

    $memoryGrowth = 0.0;
    foreach ($memoryStarts as $index => $startMemory) {
        $memoryGrowth = max($memoryGrowth, $memoryEnds[$index] - $startMemory);
    }
    $peakMemory = $memoryPeaks === [] ? null : max($memoryPeaks);
    $p99 = percentile($latencies, 99);

    if ($p99 !== null && $p99 > MAX_P99_LATENCY_MS) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute p99 latency budget.');
    }
    if ($peakMemory !== null && $peakMemory > MAX_PEAK_MEMORY_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute peak-memory budget.');
    }
    if ($memoryGrowth > MAX_MEMORY_GROWTH_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute memory-growth budget.');
    }

    return buildWorkloadResult(
        name: 'generic-otp-generate-no-context',
        type: 'persistent-worker',
        metadata: [
            'operation' => 'GenericOtp::generate on one reused service instance',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'none',
            'backend_connections' => 0,
            'duration_per_repetition_seconds' => $duration,
            'soak_duration_seconds' => $duration * $repetitions,
            'stability_spread_limit_percent' => STABILITY_SPREAD_PERCENT,
            'p99_latency_budget_ms' => MAX_P99_LATENCY_MS,
            'peak_memory_budget_mb' => MAX_PEAK_MEMORY_MB,
            'memory_growth_budget_mb' => MAX_MEMORY_GROWTH_MB,
        ],
        repetitions: $repetitions,
        warmupOperations: WARMUP_OPERATIONS,
        durationSeconds: $duration * $repetitions,
        attempted: $attempted,
        successful: $successful,
        failed: $failed,
        rpms: $rpms,
        latencies: $latencies,
        cpu: [
            'average_percent' => $wallSeconds > 0.0 ? ($cpuSeconds / $wallSeconds) * 100 : null,
            'peak_percent' => null,
        ],
        memory: [
            'average_mb' => ($memoryStarts === [] || $memoryEnds === [])
                ? null
                : (array_sum($memoryStarts) + array_sum($memoryEnds)) / (count($memoryStarts) * 2),
            'peak_mb' => $peakMemory,
            'growth_mb' => $memoryGrowth,
        ],
        stabilityLimit: STABILITY_SPREAD_PERCENT,
        unstableStatus: 'unstable',
    );
}

/**
 * @return array<string, mixed>
 */
function runColdStartWorkload(string $autoload, int $repetitions): array
{
    $rpms = [];
    $latencies = [];
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $wallSeconds = 0.0;
    $warmupOperations = 3;

    for ($repetition = 0; $repetition < $repetitions; $repetition++) {
        for ($index = 0; $index < $warmupOperations; $index++) {
            runColdStartOperation($autoload);
        }

        $start = hrtime(true);
        $repSuccessful = 0;
        for ($index = 0; $index < COLD_START_OPERATIONS; $index++) {
            $before = hrtime(true);
            if (runColdStartOperation($autoload)) {
                $repSuccessful++;
                $successful++;
            } else {
                $failed++;
            }
            $attempted++;
            $latencies[] = (hrtime(true) - $before) / 1_000_000;
        }
        $elapsed = (hrtime(true) - $start) / 1_000_000_000;
        $wallSeconds += $elapsed;
        $rpms[] = $elapsed > 0.0 ? ($repSuccessful / $elapsed) * 60 : 0.0;
    }

    if ($failed !== 0) {
        throw new RuntimeException('Cold-start benchmark recorded failed operations.');
    }

    return buildWorkloadResult(
        name: 'generic-otp-php-process-cold-start',
        type: 'custom',
        metadata: [
            'operation' => 'fresh PHP process + Composer autoload + CacheLayer + GenericOtp::generate',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'operations_per_repetition' => COLD_START_OPERATIONS,
            'stability_spread_limit_percent' => COLD_START_STABILITY_SPREAD_PERCENT,
        ],
        repetitions: $repetitions,
        warmupOperations: $warmupOperations,
        durationSeconds: $wallSeconds,
        attempted: $attempted,
        successful: $successful,
        failed: $failed,
        rpms: $rpms,
        latencies: $latencies,
        cpu: [
            'average_percent' => null,
            'peak_percent' => null,
        ],
        memory: [
            'average_mb' => null,
            'peak_mb' => null,
            'growth_mb' => null,
        ],
        stabilityLimit: COLD_START_STABILITY_SPREAD_PERCENT,
        unstableStatus: 'unverified',
    );
}

function runColdStartOperation(string $autoload): bool
{
    $code = <<<'PHP'
require $argv[1];

$cache = \Infocyph\CacheLayer\Cache\Cache::memory(
    'otp-cold-start',
    new \Infocyph\CacheLayer\Cache\CacheOptions(
        integrityKey: str_repeat('i', 32),
        allowClosures: false,
        allowObjects: false,
        failOpen: false,
    ),
);
$otp = new \Infocyph\OTP\GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
$generated = $otp->generate('cold-start');

exit(strlen($generated) === 6 && ctype_digit($generated) ? 0 : 2);
PHP;

    $process = proc_open(
        [PHP_BINARY, '-d', 'opcache.enable_cli=0', '-r', $code, '--', $autoload],
        [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
    );
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the cold-start benchmark process.');
    }

    foreach ($pipes as $pipe) {
        stream_get_contents($pipe);
        fclose($pipe);
    }

    return proc_close($process) === 0;
}
