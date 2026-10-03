<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;
const DEFAULT_DURATION_SECONDS = 8.0;
const DEFAULT_REPETITIONS = 3;
const STABILITY_SPREAD_PERCENT = 3.0;
const WARMUP_OPERATIONS = 5_000;

$options = getopt('', [
    'autoload:',
    'duration::',
    'output:',
    'release:',
    'repetitions::',
    'stable',
]);

$autoload = $options['autoload'] ?? null;
$output = $options['output'] ?? null;
$release = $options['release'] ?? null;
$duration = isset($options['duration']) ? (float) $options['duration'] : DEFAULT_DURATION_SECONDS;
$repetitions = isset($options['repetitions']) ? (int) $options['repetitions'] : DEFAULT_REPETITIONS;
$stableEnvironment = array_key_exists('stable', $options);

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

require $autoload;

$workload = runWorkload($duration, $repetitions);
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
    "Sustained benchmark: %.2f successful RPM, %.2f%% spread, %s environment\n",
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
 * @return array<string, mixed>
 */
function runWorkload(float $duration, int $repetitions): array
{
    $rpms = [];
    $latencies = [];
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $timeouts = 0;
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

    $rpmMedian = median($rpms);
    $spread = $rpmMedian > 0.0
        ? ((max($rpms) - min($rpms)) / $rpmMedian) * 100
        : 100.0;
    $latencyAverage = $latencies === [] ? null : array_sum($latencies) / count($latencies);
    $memoryGrowth = 0.0;
    foreach ($memoryStarts as $index => $startMemory) {
        $memoryGrowth = max($memoryGrowth, $memoryEnds[$index] - $startMemory);
    }

    return [
        'name' => 'generic-otp-generate-no-context',
        'type' => 'persistent-worker',
        'metadata' => [
            'operation' => 'GenericOtp::generate on one reused service instance',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'none',
            'backend_connections' => 0,
            'duration_per_repetition_seconds' => $duration,
            'stability_spread_limit_percent' => STABILITY_SPREAD_PERCENT,
        ],
        'repetitions' => $repetitions,
        'warmup_operations' => WARMUP_OPERATIONS,
        'duration_seconds' => $duration * $repetitions,
        'concurrency' => 1,
        'result' => [
            'attempted_operations' => $attempted,
            'successful_operations' => $successful,
            'failed_operations' => $failed,
            'timeouts' => $timeouts,
            'successful_rpm' => round($rpmMedian, 5),
            'error_rate' => $attempted === 0 ? 0.0 : $failed / $attempted,
            'latency_ms' => [
                'minimum' => $latencies === [] ? null : min($latencies),
                'average' => $latencyAverage,
                'p50' => percentile($latencies, 50),
                'p95' => percentile($latencies, 95),
                'p99' => percentile($latencies, 99),
                'maximum' => $latencies === [] ? null : max($latencies),
            ],
            'cpu' => [
                'average_percent' => $wallSeconds > 0.0 ? ($cpuSeconds / $wallSeconds) * 100 : null,
                'peak_percent' => null,
            ],
            'memory' => [
                'average_mb' => ($memoryStarts === [] || $memoryEnds === [])
                    ? null
                    : (array_sum($memoryStarts) + array_sum($memoryEnds)) / (count($memoryStarts) * 2),
                'peak_mb' => $memoryPeaks === [] ? null : max($memoryPeaks),
                'growth_mb' => $memoryGrowth,
            ],
            'stability' => [
                'status' => $spread <= STABILITY_SPREAD_PERCENT ? 'stable' : 'unstable',
                'spread_percent' => round($spread, 5),
            ],
        ],
    ];
}
