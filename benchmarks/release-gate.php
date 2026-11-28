<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;

const COLD_START_OPERATIONS = 30;
const COLD_START_STABILITY_SPREAD_PERCENT = 10.0;
const CONCURRENT_STABILITY_SPREAD_PERCENT = 5.0;
const CONCURRENT_WARMUP_OPERATIONS = 256;
const CONCURRENT_WARMUP_SECONDS = 5;
const CONCURRENT_WORKERS = 4;
const DEFAULT_DURATION_SECONDS = 8.0;
const DEFAULT_REPETITIONS = 3;
const MAX_MEMORY_GROWTH_MB = 8.0;
const MAX_P99_LATENCY_MS = 1.0;
const MAX_PEAK_MEMORY_MB = 64.0;
const RUNWIRE_STABILITY_SPREAD_PERCENT = 5.0;
const RUNWIRE_WARMUP_OPERATIONS = 500;
const STABILITY_SPREAD_PERCENT = 3.0;
const WARMUP_OPERATIONS = 5_000;

$options = getopt('', [
    'autoload:',
    'duration::',
    'build-report',
    'concurrent-trial',
    'release:',
    'repetitions::',
    'stable',
    'workload::',
]);
if ($options === false) {
    throw new RuntimeException('Unable to parse benchmark arguments.');
}

$autoload = $options['autoload'] ?? null;
$buildReport = array_key_exists('build-report', $options);
$release = $options['release'] ?? null;
$rawDuration = $options['duration'] ?? (string) DEFAULT_DURATION_SECONDS;
$rawRepetitions = $options['repetitions'] ?? (string) DEFAULT_REPETITIONS;
if (!is_string($rawDuration) || !is_numeric($rawDuration) || !is_string($rawRepetitions) || !ctype_digit($rawRepetitions)) {
    throw new RuntimeException('Benchmark duration and repetitions must be numeric scalar arguments.');
}
$duration = (float) $rawDuration;
$repetitions = (int) $rawRepetitions;
$stableEnvironment = array_key_exists('stable', $options);
$workloadName = $options['workload'] ?? 'sustained';

if (!is_string($autoload) || $autoload === '' || !is_file($autoload)) {
    throw new RuntimeException('A readable --autoload path is required.');
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
if (!in_array($workloadName, ['cold-start', 'concurrent-verify', 'roundtrip', 'runwire-lifecycle', 'sustained'], true)) {
    throw new RuntimeException('--workload must be cold-start, concurrent-verify, roundtrip, runwire-lifecycle, or sustained.');
}

$autoload = realpath($autoload);
if ($autoload === false) {
    throw new RuntimeException('Unable to resolve benchmark autoload path.');
}
if (!in_array($autoload, get_included_files(), true)) {
    if ($autoload !== realpath(__DIR__ . '/../vendor/autoload.php')) {
        throw new RuntimeException('External benchmark autoload must be preloaded with PHP auto_prepend_file.');
    }
    require_once __DIR__ . '/../vendor/autoload.php';
}

if ($workloadName === 'cold-start' && $autoload !== realpath(__DIR__ . '/../vendor/autoload.php')) {
    throw new RuntimeException('Cold-start measurement requires the local checkout autoloader.');
}

if (array_key_exists('concurrent-trial', $options)) {
    if ($workloadName !== 'concurrent-verify' || $buildReport || !$stableEnvironment) {
        throw new RuntimeException('A raw concurrent trial requires --workload=concurrent-verify and --stable, without --build-report.');
    }
    $measurement = measureConcurrentVerification($duration, 0);
    if ($measurement['failed'] !== 0 || $measurement['successful'] < 1) {
        throw new RuntimeException('Concurrent verification trial failed.');
    }
    $raw = json_encode([
        'environment' => environment(false, $release),
        'duration' => $duration,
        'concurrency' => CONCURRENT_WORKERS,
        'warmup_seconds' => CONCURRENT_WARMUP_SECONDS,
        'warmup_operations_minimum' => CONCURRENT_WARMUP_OPERATIONS * CONCURRENT_WORKERS,
        'stability_limit' => CONCURRENT_STABILITY_SPREAD_PERCENT,
        'measurement' => $measurement,
    ], JSON_THROW_ON_ERROR);
    if (fwrite(STDOUT, $raw . PHP_EOL) === false) {
        throw new RuntimeException('Unable to write raw concurrent trial.');
    }
    exit(0);
}

$workload = match ($workloadName) {
    'cold-start' => runColdStartWorkload($repetitions),
    'concurrent-verify' => runConcurrentVerificationWorkload($duration, $repetitions),
    'roundtrip' => runRoundTripWorkload($duration, $repetitions),
    'runwire-lifecycle' => runRunwireLifecycleWorkload($duration, $repetitions),
    default => runSustainedWorkload($duration, $repetitions),
};
$environmentStable = $stableEnvironment
    && $workload['result']['stability']['status'] === 'stable';
$document = [
    'schema_version' => 1,
    'generated_at' => gmdate('c'),
    'environment' => environment($environmentStable, $release),
    'workloads' => [$workload],
];

$json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
if ($buildReport) {
    $directory = __DIR__ . '/../build';
    if (!is_dir($directory) && !mkdir($directory, 0777, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create benchmark output directory.');
    }
    if (file_put_contents($directory . '/benchmark-result.json', $json . PHP_EOL) === false) {
        throw new RuntimeException('Unable to write benchmark result.');
    }
} elseif (fwrite(STDOUT, $json . PHP_EOL) === false) {
    throw new RuntimeException('Unable to write benchmark result.');
}

fprintf(
    STDERR,
    "%s benchmark: %.2f successful RPM, %.2f%% spread, %s environment\n",
    ucfirst(str_replace('-', ' ', $workloadName)),
    $workload['result']['successful_rpm'],
    $workload['result']['stability']['spread_percent'],
    $environmentStable ? 'stable' : 'unverified',
);

if ($workloadName === 'sustained') {
    enforceSustainedBudgets(
        $workload['result']['latency_ms']['p99'],
        $workload['result']['memory']['peak_mb'],
        $workload['result']['memory']['growth_mb'],
    );
}

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
    $runnerValue = getenv('OTP_BENCHMARK_RUNNER');
    $runner = $runnerValue === false || $runnerValue === '' ? 'local-cli' : $runnerValue;
    $fingerprint = getenv('OTP_BENCHMARK_FINGERPRINT');

    if (!is_string($fingerprint) || $fingerprint === '') {
        $fingerprint = hash('sha256', implode('|', [
            PHP_VERSION,
            PHP_SAPI,
            $operatingSystem,
            $cpuModel,
            ini_get('memory_limit'),
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
        'memory_limit' => ini_get('memory_limit'),
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

/**
 * @param array<array-key, mixed>|false $usage
 * @throws \RuntimeException
 */
function cpuSeconds(array|false $usage): float
{
    if ($usage === false) {
        throw new RuntimeException('Unable to measure process CPU usage.');
    }

    $seconds = 0.0;
    foreach (['ru_utime.tv_sec', 'ru_utime.tv_usec', 'ru_stime.tv_sec', 'ru_stime.tv_usec'] as $key) {
        $value = $usage[$key] ?? null;
        if (!is_int($value)) {
            throw new RuntimeException('Invalid process CPU usage measurement.');
        }
        $seconds += str_ends_with($key, '.tv_usec') ? (float) $value / 1_000_000.0 : (float) $value;
    }

    return $seconds;
}

/**
 * @param non-empty-list<float> $values
 */
function median(array $values): float
{
    sort($values);
    $count = count($values);
    $middle = intdiv($count, 2);

    return $count % 2 === 1
        ? $values[$middle]
        : ($values[$middle - 1] + $values[$middle]) / 2.0;
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
    $index = (int) ceil(($percentile / 100.0) * (float) count($values)) - 1;

    return $values[max(0, min(count($values) - 1, $index))];
}

/**
 * @param array<string, mixed> $metadata
 * @param non-empty-list<float> $rpms
 * @param list<float> $latencies
 * @param array{average_percent:?float,peak_percent:?float} $cpu
 * @param array{average_mb:?float,peak_mb:?float,growth_mb:?float} $memory
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
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
    int $concurrency = 1,
): array {
    $rpmMedian = median($rpms);
    $spread = $rpmMedian > 0.0
        ? ((max($rpms) - min($rpms)) / $rpmMedian) * 100.0
        : 100.0;

    return [
        'name' => $name,
        'type' => $type,
        'metadata' => $metadata,
        'repetitions' => $repetitions,
        'warmup_operations' => $warmupOperations,
        'duration_seconds' => $durationSeconds,
        'concurrency' => $concurrency,
        'result' => [
            'attempted_operations' => $attempted,
            'successful_operations' => $successful,
            'failed_operations' => $failed,
            'timeouts' => 0,
            'successful_rpm' => round($rpmMedian, 5),
            'error_rate' => $attempted === 0 ? 0.0 : $failed / $attempted,
            'latency_ms' => [
                'minimum' => $latencies === [] ? null : min($latencies),
                'average' => $latencies === [] ? null : array_sum($latencies) / (float) count($latencies),
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
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runSustainedWorkload(float $duration, int $repetitions): array
{
    return runTimedWorkload(
        $duration,
        $repetitions,
        'generic-otp-generate-no-context',
        [
            'operation' => 'GenericOtp::generate on one reused service instance',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'none',
            'backend_connections' => 0,
        ],
        WARMUP_OPERATIONS,
        STABILITY_SPREAD_PERCENT,
        100,
        static function (int $repetition): \Closure {
            $cache = Cache::memory('otp-release-generate-' . $repetition, benchmarkCacheOptions());
            $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);

            return static function () use ($otp): void {
                $code = $otp->generate('release-gate');
                if (strlen($code) !== 6 || !ctype_digit($code)) {
                    throw new RuntimeException('Generic OTP benchmark produced an invalid code.');
                }
            };
        },
        true,
    );
}

/**
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runRoundTripWorkload(float $duration, int $repetitions): array
{
    return runTimedWorkload(
        $duration,
        $repetitions,
        'generic-otp-request-roundtrip',
        [
            'operation' => 'GenericOtp::generate + successful verify on one reused service instance',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'none',
            'backend_connections' => 0,
        ],
        WARMUP_OPERATIONS,
        STABILITY_SPREAD_PERCENT,
        100,
        static function (int $repetition): \Closure {
            $cache = Cache::memory('otp-release-roundtrip-' . $repetition, benchmarkCacheOptions());
            $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);

            return static function () use ($otp): void {
                $code = $otp->generate('release-gate-roundtrip');
                if (!$otp->verify('release-gate-roundtrip', $code)) {
                    throw new RuntimeException('Generic OTP round-trip benchmark failed verification.');
                }
            };
        },
    );
}

/**
 * @param array<string, mixed> $metadata
 * @param callable(int): \Closure $operationFactory
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runTimedWorkload(
    float $duration,
    int $repetitions,
    string $name,
    array $metadata,
    int $warmupOperations,
    float $stabilityLimit,
    int $sampleInterval,
    callable $operationFactory,
    bool $enforceAbsoluteBudgets = false,
): array {
    $metadata['duration_per_repetition_seconds'] = $duration;
    $metadata['soak_duration_seconds'] = $duration * (float) $repetitions;
    $metadata['stability_spread_limit_percent'] = $stabilityLimit;
    if ($enforceAbsoluteBudgets) {
        $metadata['p99_latency_budget_ms'] = MAX_P99_LATENCY_MS;
        $metadata['peak_memory_budget_mb'] = MAX_PEAK_MEMORY_MB;
        $metadata['memory_growth_budget_mb'] = MAX_MEMORY_GROWTH_MB;
    }

    $workload = runRepeatedWorkload(
        $repetitions,
        $name,
        'persistent-worker',
        $metadata,
        $warmupOperations,
        $stabilityLimit,
        static function (int $repetition) use (
            $duration,
            $sampleInterval,
            $operationFactory,
            $warmupOperations,
        ): array {
            $operation = $operationFactory($repetition);
            for ($index = 0; $index < $warmupOperations; $index++) {
                $operation();
            }

            return measureOperation($operation, $duration, $sampleInterval);
        },
    );
    $workload['duration_seconds'] = $duration * (float) $repetitions;

    return $workload;
}

/** @throws RuntimeException */
function enforceSustainedBudgets(?float $p99, ?float $peakMemory, ?float $memoryGrowth): void
{
    if ($p99 === null || $peakMemory === null || $memoryGrowth === null) {
        throw new RuntimeException('Sustained benchmark did not report all required budget metrics.');
    }
    if ($p99 > MAX_P99_LATENCY_MS) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute p99 latency budget.');
    }
    if ($peakMemory > MAX_PEAK_MEMORY_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute peak-memory budget.');
    }
    if ($memoryGrowth > MAX_MEMORY_GROWTH_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute memory-growth budget.');
    }
}

/**
 * @param array<string, mixed> $metadata
 * @param callable(int): array{attempted:int,successful:int,failed:int,latencies:list<float>,elapsed:float,cpu_seconds:?float,memory_start_mb:?float,memory_end_mb:?float,memory_peak_mb:?float,successful_rpm:float} $repetitionOperation
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runRepeatedWorkload(
    int $repetitions,
    string $name,
    string $type,
    array $metadata,
    int $warmupOperations,
    float $stabilityLimit,
    callable $repetitionOperation,
    string $unstableStatus = 'unstable',
    int $concurrency = 1,
): array {
    if ($repetitions < 1) {
        throw new RuntimeException('Benchmark requires at least one repetition.');
    }
    $rpms = [];
    $latencies = [];
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $wallSeconds = 0.0;
    $cpuSeconds = 0.0;
    $cpuMeasured = false;
    $memoryStarts = [];
    $memoryEnds = [];
    $memoryPeaks = [];

    for ($repetition = 0; $repetition < $repetitions; $repetition++) {
        $measurement = $repetitionOperation($repetition);
        $attempted += $measurement['attempted'];
        $successful += $measurement['successful'];
        $failed += $measurement['failed'];
        $wallSeconds += $measurement['elapsed'];
        $rpms[] = $measurement['successful_rpm'];
        $latencies = [...$latencies, ...$measurement['latencies']];

        if (is_float($measurement['cpu_seconds'])) {
            $cpuSeconds += $measurement['cpu_seconds'];
            $cpuMeasured = true;
        }
        appendMemorySamples($measurement, $memoryStarts, $memoryEnds, $memoryPeaks);
    }

    if ($failed !== 0) {
        throw new RuntimeException('Representative benchmark recorded failed operations or no measurements.');
    }

    $memoryGrowth = maximumMemoryGrowth($memoryStarts, $memoryEnds);

    return buildWorkloadResult(
        name: $name,
        type: $type,
        metadata: $metadata,
        repetitions: $repetitions,
        warmupOperations: $warmupOperations,
        durationSeconds: $wallSeconds,
        attempted: $attempted,
        successful: $successful,
        failed: $failed,
        rpms: $rpms,
        latencies: $latencies,
        cpu: [
            'average_percent' => $cpuMeasured && $wallSeconds > 0.0 ? ($cpuSeconds / $wallSeconds) * 100.0 : null,
            'peak_percent' => null,
        ],
        memory: [
            'average_mb' => ($memoryStarts === [] || $memoryEnds === [])
                ? null
                : (array_sum($memoryStarts) + array_sum($memoryEnds)) / (float) (count($memoryStarts) * 2),
            'peak_mb' => $memoryPeaks === [] ? null : max($memoryPeaks),
            'growth_mb' => $memoryGrowth,
        ],
        stabilityLimit: $stabilityLimit,
        unstableStatus: $unstableStatus,
        concurrency: $concurrency,
    );
}

/**
 * @param array{memory_start_mb:?float,memory_end_mb:?float,memory_peak_mb:?float,...} $measurement
 * @param list<float> $starts
 * @param list<float> $ends
 * @param list<float> $peaks
 */
function appendMemorySamples(array $measurement, array &$starts, array &$ends, array &$peaks): void
{
    if (is_float($measurement['memory_start_mb'])) {
        $starts[] = $measurement['memory_start_mb'];
    }
    if (is_float($measurement['memory_end_mb'])) {
        $ends[] = $measurement['memory_end_mb'];
    }
    if (is_float($measurement['memory_peak_mb'])) {
        $peaks[] = $measurement['memory_peak_mb'];
    }
}

/**
 * @param list<float> $starts
 * @param list<float> $ends
 */
function maximumMemoryGrowth(array $starts, array $ends): ?float
{
    if ($starts === [] || count($starts) !== count($ends)) {
        return null;
    }
    $growth = 0.0;
    foreach ($starts as $index => $start) {
        $growth = max($growth, $ends[$index] - $start);
    }

    return $growth;
}

/**
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runConcurrentVerificationWorkload(float $duration, int $repetitions): array
{
    if (!extension_loaded('pcntl') || !extension_loaded('posix') || !extension_loaded('pdo_sqlite')) {
        throw new RuntimeException('Concurrent verification benchmark requires pcntl, posix, and pdo_sqlite.');
    }

    $workload = runRepeatedWorkload(
        $repetitions,
        'generic-otp-concurrent-verification',
        'persistent-worker',
        [
            'operation' => 'four persistent workers performing GenericOtp::generate + verify',
            'backend' => 'CacheLayer SQLite authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'synchronized warmup and common measurement deadline',
            'warmup_seconds' => CONCURRENT_WARMUP_SECONDS,
            'backend_connections' => CONCURRENT_WORKERS,
            'memory_measurement' => 'parent and all ready workers RSS sampled every 10ms during load',
            'duration_per_repetition_seconds' => $duration,
            'soak_duration_seconds' => $duration * (float) $repetitions,
            'stability_spread_limit_percent' => CONCURRENT_STABILITY_SPREAD_PERCENT,
        ],
        CONCURRENT_WARMUP_OPERATIONS * CONCURRENT_WORKERS,
        CONCURRENT_STABILITY_SPREAD_PERCENT,
        static fn(int $repetition): array => measureConcurrentVerification($duration, $repetition),
        concurrency: CONCURRENT_WORKERS,
    );
    $workload['duration_seconds'] = $duration * (float) $repetitions;

    return $workload;
}

/**
 * @return array{attempted:int,successful:int,failed:int,latencies:list<float>,elapsed:float,cpu_seconds:float,memory_start_mb:?float,memory_end_mb:?float,memory_peak_mb:?float,successful_rpm:float}
 * @throws Throwable
 */
function measureConcurrentVerification(float $duration, int $repetition): array
{
    $database = sys_get_temp_dir() . '/otp-release-concurrent-' . bin2hex(random_bytes(8)) . '.sqlite';
    $barrier = sys_get_temp_dir() . '/otp-release-barrier-' . bin2hex(random_bytes(8));
    $namespace = 'otp-release-concurrent-' . $repetition;
    $initializer = Cache::sqlite($namespace, $database, benchmarkCacheOptions());
    $initializer->set('ready', true, 60);
    unset($initializer);
    $children = [];

    try {
        startConcurrentWorkers($children, $database, $namespace, $barrier, $duration);
        awaitConcurrentBarrier($children, $barrier);
        $parentPid = getmypid();
        if ($parentPid === false) {
            throw new RuntimeException('Unable to identify benchmark parent process.');
        }
        $pids = [$parentPid, ...array_values($children)];
        $start = hrtime(true) + CONCURRENT_WARMUP_SECONDS * 1_000_000_000;
        if (file_put_contents($barrier . '.go.tmp', (string) $start) === false
            || !rename($barrier . '.go.tmp', $barrier . '.go')) {
            throw new RuntimeException('Unable to start concurrent verification warmup.');
        }
        while (hrtime(true) < $start) {
            usleep(1_000);
        }
        $usageBefore = getrusage();
        $memoryStart = processRssMegabytes($pids);
        clearstatcache(true, $database . '-wal');
        $walStart = is_file($database . '-wal') ? filesize($database . '-wal') : 0;
        [$memoryEnd, $memoryPeak] = sampleConcurrentWorkers($children, $pids, $barrier, $duration, $start, $memoryStart);
        $elapsed = (hrtime(true) - $start) / 1_000_000_000;
        clearstatcache(true, $database . '-wal');
        $walEnd = is_file($database . '-wal') ? filesize($database . '-wal') : 0;
        fprintf(STDERR, "Concurrent trial WAL bytes: %s -> %s\n", (string) $walStart, (string) $walEnd);
        file_put_contents($barrier . '.stop', '1');
        joinConcurrentWorkers($children);
        $cpu = cpuSeconds(getrusage()) - cpuSeconds($usageBefore);
        $result = readConcurrentResults($children, $barrier, $cpu);

        return $result + [
            'elapsed' => $elapsed,
            'memory_start_mb' => $memoryStart,
            'memory_end_mb' => $memoryEnd,
            'memory_peak_mb' => $memoryPeak,
            'successful_rpm' => $elapsed > 0.0 ? ((float) $result['successful'] / (float) $elapsed) * 60.0 : 0.0,
        ];
    } finally {
        foreach ($children as $pid) {
            if (pcntl_waitpid($pid, $status, WNOHANG) === 0) {
                posix_kill($pid, SIGTERM);
                pcntl_waitpid($pid, $status);
            }
        }
        cleanupConcurrentBenchmark($database, $barrier);
    }
}

/**
 * @param array<int, int> $children
 * @throws RuntimeException
 * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
 * @throws \InvalidArgumentException
 * @throws \LogicException
 * @throws \Throwable
 */
function startConcurrentWorkers(array &$children, string $database, string $namespace, string $barrier, float $duration): void
{
    for ($worker = 0; $worker < CONCURRENT_WORKERS; $worker++) {
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException('Unable to fork concurrent verification benchmark worker.');
        }
        if ($pid === 0) {
            runConcurrentVerificationWorker($database, $namespace, $barrier, $worker, $duration);
            exit(0);
        }
        $children[$worker] = $pid;
    }
}

/**
 * @param array<int, int> $children
 * @throws RuntimeException
 */
function awaitConcurrentBarrier(array $children, string $barrier): void
{
    $deadline = microtime(true) + 15.0;
    foreach (array_keys($children) as $worker) {
        while (!is_file($barrier . '.ready.' . $worker)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Concurrent verification worker did not reach the start barrier.');
            }
            usleep(1_000);
        }
    }
}

/**
 * @param array<int, int> $children
 * @param list<int> $pids
 * @return array{?float,?float}
 * @throws RuntimeException
 */
function sampleConcurrentWorkers(array $children, array $pids, string $barrier, float $duration, int $start, ?float $memoryStart): array
{
    $memoryEnd = $memoryStart;
    $memoryPeak = $memoryStart;
    do {
        $sample = processRssMegabytes($pids);
        if ($sample !== null) {
            $memoryEnd = $sample;
            $memoryPeak = max($memoryPeak ?? $sample, $sample);
        }
        $ready = countConcurrentResults($children, $barrier);
        if ((hrtime(true) - $start) / 1_000_000_000 > $duration + 15.0) {
            throw new RuntimeException('Concurrent verification workers exceeded their completion deadline.');
        }
        usleep(10_000);
    } while ($ready < count($children));

    return [$memoryEnd, $memoryPeak];
}

/**
 * @param array<int, int> $children
 * @throws RuntimeException
 */
function countConcurrentResults(array $children, string $barrier): int
{
    $ready = 0;
    foreach ($children as $worker => $pid) {
        if (pcntl_waitpid($pid, $status, WNOHANG) !== 0) {
            throw new RuntimeException('Concurrent verification worker exited before resource sampling completed.');
        }
        $ready += is_file($barrier . '.result.' . $worker) ? 1 : 0;
    }

    return $ready;
}

function workerExitedSuccessfully(mixed $status): bool
{
    return is_int($status) && pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0;
}

/**
 * @param array<int, int> $children
 * @throws RuntimeException
 */
function joinConcurrentWorkers(array $children): void
{
    foreach ($children as $pid) {
        $status = 0;
        if (pcntl_waitpid($pid, $status) !== $pid || !workerExitedSuccessfully($status)) {
            throw new RuntimeException('Concurrent verification worker exited unsuccessfully.');
        }
    }
}

/**
 * @param array<int, int> $children
 * @return array{attempted:int,successful:int,failed:int,latencies:list<float>,cpu_seconds:float}
 * @throws RuntimeException
 * @throws JsonException
 */
function readConcurrentResults(array $children, string $barrier, float $cpu): array
{
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $latencies = [];
    foreach (array_keys($children) as $worker) {
        $result = readConcurrentResult($barrier . '.result.' . $worker);
        fprintf(STDERR, "Concurrent worker %d: %d successful, %d failed, %.6f CPU seconds\n", $worker, $result['successful'], $result['failed'], $result['cpu_seconds']);
        $cpu += $result['cpu_seconds'];
        $attempted += $result['attempted'];
        $successful += $result['successful'];
        $failed += $result['failed'];
        $latencies = [...$latencies, ...$result['latencies']];
    }

    return [
        'attempted' => $attempted,
        'successful' => $successful,
        'failed' => $failed,
        'latencies' => $latencies,
        'cpu_seconds' => $cpu,
    ];
}

/**
 * @return array{attempted:int,successful:int,failed:int,latencies:list<float>,cpu_seconds:float}
 * @throws RuntimeException
 * @throws JsonException
 */
function readConcurrentResult(string $path): array
{
    $payload = file_get_contents($path);
    if (!is_string($payload)) {
        throw new RuntimeException('Concurrent verification worker returned no benchmark result.');
    }
    $result = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($result)
        || !isset($result['attempted'], $result['successful'], $result['failed'], $result['latencies'], $result['cpu_seconds'])
        || !is_int($result['attempted'])
        || !is_int($result['successful'])
        || !is_int($result['failed'])
        || !is_array($result['latencies'])
        || !is_numeric($result['cpu_seconds'])) {
        throw new RuntimeException('Invalid concurrent verification measurement.');
    }
    $latencies = [];
    foreach ($result['latencies'] as $latency) {
        if (!is_float($latency) && !is_int($latency)) {
            throw new RuntimeException('Invalid concurrent verification latency.');
        }
        $latencies[] = (float) $latency;
    }

    return [
        'attempted' => $result['attempted'],
        'successful' => $result['successful'],
        'failed' => $result['failed'],
        'latencies' => $latencies,
        'cpu_seconds' => (float) $result['cpu_seconds'],
    ];
}

/** @param list<int> $pids */
function processRssMegabytes(array $pids): ?float
{
    $kilobytes = 0;
    foreach ($pids as $pid) {
        $path = '/proc/' . $pid . '/status';
        if (!is_readable($path)) {
            return null;
        }
        $status = file_get_contents($path);
        if (!is_string($status) || preg_match('/^VmRSS:\s+(\d+) kB$/m', $status, $match) !== 1) {
            return null;
        }
        $kilobytes += (int) $match[1];
    }

    return (float) $kilobytes / 1024.0;
}

/**
 * @throws \Infocyph\CacheLayer\Cache\Lock\UnsupportedPdoLockDriver
 * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
 * @throws \Infocyph\Runwire\Exception\CancelledException
 * @throws \InvalidArgumentException
 * @throws \LogicException
 * @throws \RuntimeException
 * @throws \Throwable
 */
function runConcurrentVerificationWorker(
    string $database,
    string $namespace,
    string $barrier,
    int $worker,
    float $duration,
): void {
    $cache = Cache::sqlite($namespace, $database, benchmarkCacheOptions());
    $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
    $sequence = 0;

    for ($index = 0; $index < CONCURRENT_WARMUP_OPERATIONS; $index++) {
        $binding = 'worker-' . $worker . '-' . ($index % 128);
        $code = $otp->generate($binding);
        if (!$otp->verify($binding, $code)) {
            throw new RuntimeException('Concurrent verification warmup failed.');
        }
    }

    if (file_put_contents($barrier . '.ready.' . $worker, '1') === false) {
        throw new RuntimeException('Unable to signal concurrent worker readiness.');
    }
    $readyDeadline = hrtime(true) + 20_000_000_000;
    while (!is_file($barrier . '.go')) {
        if (hrtime(true) >= $readyDeadline) {
            throw new RuntimeException('Concurrent worker warmup barrier timed out.');
        }
        usleep(500);
    }
    $rawStart = file_get_contents($barrier . '.go');
    if (!is_string($rawStart) || !ctype_digit($rawStart)) {
        throw new RuntimeException('Invalid concurrent verification start timestamp.');
    }
    $start = (int) $rawStart;

    $operation = static function () use ($otp, $worker, &$sequence): void {
        $binding = 'worker-' . $worker . '-' . ($sequence % 128);
        $sequence++;
        $code = $otp->generate($binding);
        if (!$otp->verify($binding, $code)) {
            throw new RuntimeException('Concurrent GenericOtp verification was rejected.');
        }
    };
    while (hrtime(true) < $start) {
        $operation();
    }
    fprintf(STDERR, "Concurrent worker %d: %d sustained warmup operations\n", $worker, $sequence);
    $measurement = measureOperation($operation, $duration, 20, $start + (int) round($duration * 1_000_000_000.0));
    $payload = json_encode([
        'attempted' => $measurement['attempted'],
        'successful' => $measurement['successful'],
        'failed' => $measurement['failed'],
        'latencies' => $measurement['latencies'],
        'cpu_seconds' => $measurement['cpu_seconds'],
    ], JSON_THROW_ON_ERROR);
    file_put_contents($barrier . '.result.' . $worker, $payload);
    while (!is_file($barrier . '.stop')) {
        usleep(1_000);
    }
}

/**
 * @throws \RuntimeException
 */
function cleanupConcurrentBenchmark(string $database, string $barrier): void
{
    $paths = [$barrier . '.go', $barrier . '.go.tmp', $barrier . '.stop', $database, $database . '-shm', $database . '-wal'];
    for ($worker = 0; $worker < CONCURRENT_WORKERS; $worker++) {
        $paths[] = $barrier . '.ready.' . $worker;
        $paths[] = $barrier . '.result.' . $worker;
    }

    foreach ($paths as $path) {
        if (is_file($path) && !unlink($path)) {
            throw new RuntimeException('Unable to remove concurrent benchmark temporary state.');
        }
    }
}

/**
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runRunwireLifecycleWorkload(float $duration, int $repetitions): array
{
    $required = [
        \Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext::class,
        \Infocyph\Runwire\Coroutine\CoroutineRuntime::class,
        \Infocyph\Runwire\RequestContext::class,
        \Infocyph\Runwire\RuntimeCapabilities::class,
        \Infocyph\Runwire\RuntimeContext::class,
    ];
    foreach ($required as $class) {
        if (!class_exists($class)) {
            throw new RuntimeException('Runwire lifecycle benchmark requires the optional Runwire development dependency.');
        }
    }

    return runTimedWorkload(
        $duration,
        $repetitions,
        'generic-otp-runwire-request-lifecycle',
        [
            'operation' => 'persistent Runwire runtime + fresh RequestContext/scope + GenericOtp generate/verify + cleanup',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'explicit request and coroutine scope',
            'queue' => 'Runwire coroutine scheduler',
            'backend_connections' => 0,
            'cleanup_assertion' => 'zero active tasks, request scopes, and background tasks after every request',
        ],
        RUNWIRE_WARMUP_OPERATIONS,
        RUNWIRE_STABILITY_SPREAD_PERCENT,
        20,
        static function (int $repetition): \Closure {
            $capabilities = new \Infocyph\Runwire\RuntimeCapabilities(
                driver: \Infocyph\Runwire\Runtime\Enum\RuntimeDriver::NATIVE,
                persistentProcess: true,
                persistentApplication: true,
                hostOwnsEventLoop: true,
                runwireLoopAvailable: true,
                supportsRunwireCoroutines: true,
                supportsHttp1: true,
            );
            $runtime = \Infocyph\Runwire\RuntimeContext::fromCapabilities(
                $capabilities,
                'otp-release',
                generation: $repetition + 1,
                concurrent: true,
            );
            $coroutines = new \Infocyph\Runwire\Coroutine\CoroutineRuntime();
            $cache = Cache::memory('otp-release-runwire-' . $repetition, benchmarkCacheOptions());
            $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
            $sequence = 0;

            return static function () use ($runtime, $coroutines, $otp, &$sequence): void {
                $request = \Infocyph\Runwire\RequestContext::create(
                    $runtime,
                    requestId: 'otp-release-' . $sequence,
                );
                $binding = 'runwire-lifecycle-' . ($sequence % 64);
                $sequence++;

                try {
                    $accepted = $coroutines->runRequest(
                        $request,
                        static function (\Infocyph\Runwire\Coroutine\CoroutineScope $scope) use (
                            $runtime,
                            $request,
                            $otp,
                            $binding,
                        ): bool {
                            $execution = new \Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext(
                                $runtime,
                                $request,
                                $scope,
                            );
                            $code = $otp->generate($binding, $execution);

                            return $otp->verify($binding, $code, $execution);
                        },
                    );
                    if (!$accepted) {
                        throw new RuntimeException('Runwire lifecycle benchmark rejected a generated OTP.');
                    }
                } finally {
                    $request->complete();
                }

                $diagnostics = $coroutines->diagnostics();
                if (
                    $diagnostics->activeTasks !== 0
                    || $diagnostics->requestScopesActive !== 0
                    || $diagnostics->backgroundTasksActive !== 0
                ) {
                    throw new RuntimeException('Runwire lifecycle benchmark leaked coroutine/request state.');
                }
            };
        },
    );
}

/**
 * @return array{
 *     attempted:int,
 *     successful:int,
 *     failed:int,
 *     latencies:list<float>,
 *     elapsed:float,
 *     cpu_seconds:float,
 *     memory_start_mb:float,
 *     memory_end_mb:float,
 *     memory_peak_mb:float,
 *     successful_rpm:float
 * }
 * @throws \RuntimeException
 */
function measureOperation(callable $operation, float $duration, int $sampleInterval, ?int $endNanoseconds = null): array
{
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $latencies = [];
    $usageBefore = getrusage();
    $memoryStart = memory_get_usage(true);
    $start = hrtime(true);
    $deadline = $endNanoseconds ?? ($start + (int) round($duration * 1_000_000_000.0));

    while (true) {
        $before = hrtime(true);
        if ($before >= $deadline) {
            break;
        }

        try {
            $operation();
            $successful++;
        } catch (Throwable) {
            $failed++;
        }
        $attempted++;

        if ($attempted % $sampleInterval === 0) {
            $latencies[] = (hrtime(true) - $before) / 1_000_000;
        }
    }

    $elapsed = (hrtime(true) - $start) / 1_000_000_000;
    $usageAfter = getrusage();

    return [
        'attempted' => $attempted,
        'successful' => $successful,
        'failed' => $failed,
        'latencies' => $latencies,
        'elapsed' => $elapsed,
        'cpu_seconds' => max(0.0, cpuSeconds($usageAfter) - cpuSeconds($usageBefore)),
        'memory_start_mb' => (float) $memoryStart / 1_048_576.0,
        'memory_end_mb' => (float) memory_get_usage(true) / 1_048_576.0,
        'memory_peak_mb' => (float) memory_get_peak_usage(true) / 1_048_576.0,
        'successful_rpm' => $elapsed > 0.0 ? ((float) $successful / (float) $elapsed) * 60.0 : 0.0,
    ];
}

/**
 * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
 */
function benchmarkCacheOptions(): CacheOptions
{
    return new CacheOptions(
        integrityKey: str_repeat('i', 32),
        allowClosures: false,
        allowObjects: false,
        failOpen: false,
    );
}

/**
 * @return array{name:string,type:string,metadata:array<string,mixed>,repetitions:int,warmup_operations:int,duration_seconds:float,concurrency:int,result:array{attempted_operations:int,successful_operations:int,failed_operations:int,timeouts:int,successful_rpm:float,error_rate:float,latency_ms:array{minimum:?float,average:?float,p50:?float,p95:?float,p99:?float,maximum:?float},cpu:array{average_percent:?float,peak_percent:?float},memory:array{average_mb:?float,peak_mb:?float,growth_mb:?float},stability:array{status:string,spread_percent:float}}}
 * @throws \RuntimeException
 */
function runColdStartWorkload(int $repetitions): array
{
    $warmupOperations = 3;

    return runRepeatedWorkload(
        $repetitions,
        'generic-otp-php-process-cold-start',
        'custom',
        [
            'operation' => 'fresh PHP process + Composer autoload + CacheLayer + GenericOtp::generate',
            'backend' => 'CacheLayer memory authoritative state',
            'runwire_context' => 'absent',
            'operations_per_repetition' => COLD_START_OPERATIONS,
            'memory_measurement' => 'maximum fresh child peak RSS from getrusage, Linux KiB',
            'stability_spread_limit_percent' => COLD_START_STABILITY_SPREAD_PERCENT,
        ],
        $warmupOperations,
        COLD_START_STABILITY_SPREAD_PERCENT,
        static function (int $repetition) use ($warmupOperations): array {
            unset($repetition);
            for ($index = 0; $index < $warmupOperations; $index++) {
                runColdStartOperation();
            }

            $start = hrtime(true);
            $successful = 0;
            $failed = 0;
            $latencies = [];
            $cpu = 0.0;
            $memoryPeak = 0.0;
            for ($index = 0; $index < COLD_START_OPERATIONS; $index++) {
                $before = hrtime(true);
                $measurement = runColdStartOperation();
                $cpu += $measurement['cpu_seconds'];
                $memoryPeak = max($memoryPeak, $measurement['memory_peak_mb']);
                if ($measurement['successful']) {
                    $successful++;
                } else {
                    $failed++;
                }
                $latencies[] = (hrtime(true) - $before) / 1_000_000;
            }
            $elapsed = (hrtime(true) - $start) / 1_000_000_000;

            return [
                'attempted' => COLD_START_OPERATIONS,
                'successful' => $successful,
                'failed' => $failed,
                'latencies' => $latencies,
                'elapsed' => $elapsed,
                'cpu_seconds' => $cpu,
                'memory_start_mb' => null,
                'memory_end_mb' => null,
                'memory_peak_mb' => $memoryPeak,
                'successful_rpm' => $elapsed > 0.0 ? ((float) $successful / (float) $elapsed) * 60.0 : 0.0,
            ];
        },
        unstableStatus: 'unverified',
    );
}

/**
 * @return array{successful:bool,cpu_seconds:float,memory_peak_mb:float}
 * @throws \RuntimeException
 */
function runColdStartOperation(): array
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

$usage = getrusage();
echo json_encode([
    'successful' => strlen($generated) === 6 && ctype_digit($generated),
    'cpu_seconds' => $usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec']
        + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) / 1_000_000.0,
    'memory_peak_mb' => $usage['ru_maxrss'] / 1024.0,
], JSON_THROW_ON_ERROR);

PHP;

    $process = proc_open(
        [PHP_BINARY, '-d', 'opcache.enable_cli=0', '-r', $code, '--', __DIR__ . '/../vendor/autoload.php'],
        [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
    );
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the cold-start benchmark process.');
    }

    $payload = stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    foreach ($pipes as $pipe) {
        fclose($pipe);
    }
    if (proc_close($process) !== 0 || !is_string($payload)) {
        throw new RuntimeException('Cold-start child failed before returning resource measurements.');
    }
    $measurement = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($measurement)
        || !isset($measurement['successful'], $measurement['cpu_seconds'], $measurement['memory_peak_mb'])
        || !is_bool($measurement['successful'])
        || !is_numeric($measurement['cpu_seconds'])
        || !is_numeric($measurement['memory_peak_mb'])
    ) {
        throw new RuntimeException('Cold-start child returned invalid resource measurements.');
    }

    return [
        'successful' => $measurement['successful'],
        'cpu_seconds' => (float) $measurement['cpu_seconds'],
        'memory_peak_mb' => (float) $measurement['memory_peak_mb'],
    ];
}
