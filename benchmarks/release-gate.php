<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\OTP\GenericOtp;

const COLD_START_OPERATIONS = 30;
const COLD_START_STABILITY_SPREAD_PERCENT = 10.0;
const CONCURRENT_STABILITY_SPREAD_PERCENT = 5.0;
const CONCURRENT_WARMUP_OPERATIONS = 50;
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
if (!in_array($workloadName, ['cold-start', 'concurrent-verify', 'roundtrip', 'runwire-lifecycle', 'sustained'], true)) {
    throw new RuntimeException('--workload must be cold-start, concurrent-verify, roundtrip, runwire-lifecycle, or sustained.');
}

require $autoload;

$workload = match ($workloadName) {
    'cold-start' => runColdStartWorkload($autoload, $repetitions),
    'concurrent-verify' => runConcurrentVerificationWorkload($duration, $repetitions),
    'roundtrip' => runRoundTripWorkload($duration, $repetitions),
    'runwire-lifecycle' => runRunwireLifecycleWorkload($duration, $repetitions),
    default => runSustainedWorkload($duration, $repetitions),
};
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
    ucfirst(str_replace('-', ' ', $workloadName)),
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
    int $concurrency = 1,
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
        static function (int $repetition): callable {
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
 * @return array<string, mixed>
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
        static function (int $repetition): callable {
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
 * @return array<string, mixed>
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

    if (!$enforceAbsoluteBudgets) {
        return $workload;
    }

    $p99 = $workload['result']['latency_ms']['p99'] ?? null;
    $peakMemory = $workload['result']['memory']['peak_mb'] ?? null;
    $memoryGrowth = $workload['result']['memory']['growth_mb'] ?? null;
    if (is_float($p99) && $p99 > MAX_P99_LATENCY_MS) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute p99 latency budget.');
    }
    if (is_float($peakMemory) && $peakMemory > MAX_PEAK_MEMORY_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute peak-memory budget.');
    }
    if (is_float($memoryGrowth) && $memoryGrowth > MAX_MEMORY_GROWTH_MB) {
        throw new RuntimeException('Sustained benchmark exceeded the absolute memory-growth budget.');
    }

    return $workload;
}

/**
 * @return array<string, mixed>
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
        if (is_float($measurement['memory_start_mb'])) {
            $memoryStarts[] = $measurement['memory_start_mb'];
        }
        if (is_float($measurement['memory_end_mb'])) {
            $memoryEnds[] = $measurement['memory_end_mb'];
        }
        if (is_float($measurement['memory_peak_mb'])) {
            $memoryPeaks[] = $measurement['memory_peak_mb'];
        }
    }

    if ($failed !== 0) {
        throw new RuntimeException('Representative benchmark recorded failed operations.');
    }

    $memoryGrowth = null;
    if ($memoryStarts !== [] && count($memoryStarts) === count($memoryEnds)) {
        $memoryGrowth = 0.0;
        foreach ($memoryStarts as $index => $startMemory) {
            $memoryGrowth = max($memoryGrowth, $memoryEnds[$index] - $startMemory);
        }
    }
    $metadata['soak_duration_seconds'] = $wallSeconds;

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
            'average_percent' => $cpuMeasured && $wallSeconds > 0.0 ? ($cpuSeconds / $wallSeconds) * 100 : null,
            'peak_percent' => null,
        ],
        memory: [
            'average_mb' => ($memoryStarts === [] || $memoryEnds === [])
                ? null
                : (array_sum($memoryStarts) + array_sum($memoryEnds)) / (count($memoryStarts) * 2),
            'peak_mb' => $memoryPeaks === [] ? null : max($memoryPeaks),
            'growth_mb' => $memoryGrowth,
        ],
        stabilityLimit: $stabilityLimit,
        unstableStatus: $unstableStatus,
        concurrency: $concurrency,
    );
}

/**
 * @return array<string, mixed>
 */
function runConcurrentVerificationWorkload(float $duration, int $repetitions): array
{
    if (!extension_loaded('pcntl') || !extension_loaded('posix') || !extension_loaded('pdo_sqlite')) {
        throw new RuntimeException('Concurrent verification benchmark requires pcntl, posix, and pdo_sqlite.');
    }

    return runRepeatedWorkload(
        $repetitions,
        'generic-otp-concurrent-verification',
        'persistent-worker',
        [
            'operation' => 'four persistent workers performing GenericOtp::generate + verify',
            'backend' => 'CacheLayer SQLite authoritative state',
            'runwire_context' => 'absent',
            'queue' => 'process start barrier only',
            'backend_connections' => CONCURRENT_WORKERS,
            'duration_per_repetition_seconds' => $duration,
            'stability_spread_limit_percent' => CONCURRENT_STABILITY_SPREAD_PERCENT,
        ],
        CONCURRENT_WARMUP_OPERATIONS * CONCURRENT_WORKERS,
        CONCURRENT_STABILITY_SPREAD_PERCENT,
        static function (int $repetition) use ($duration): array {
            $database = sys_get_temp_dir() . '/otp-release-concurrent-' . bin2hex(random_bytes(8)) . '.sqlite';
            $barrier = sys_get_temp_dir() . '/otp-release-barrier-' . bin2hex(random_bytes(8));
            $namespace = 'otp-release-concurrent-' . $repetition;
            $initializer = Cache::sqlite($namespace, $database, benchmarkCacheOptions());
            $initializer->set('ready', true, 60);
            unset($initializer);

            $children = [];
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

            $readyDeadline = microtime(true) + 15.0;
            for ($worker = 0; $worker < CONCURRENT_WORKERS; $worker++) {
                while (!is_file($barrier . '.ready.' . $worker)) {
                    if (microtime(true) >= $readyDeadline) {
                        throw new RuntimeException('Concurrent verification worker did not reach the start barrier.');
                    }
                    usleep(1_000);
                }
            }

            $start = hrtime(true);
            file_put_contents($barrier . '.go', '1');
            $attempted = 0;
            $successful = 0;
            $failed = 0;
            $latencies = [];

            foreach ($children as $worker => $pid) {
                pcntl_waitpid($pid, $status);
                if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0) {
                    throw new RuntimeException('Concurrent verification worker exited unsuccessfully.');
                }

                $payload = file_get_contents($barrier . '.result.' . $worker);
                if (!is_string($payload)) {
                    throw new RuntimeException('Concurrent verification worker returned no benchmark result.');
                }
                $result = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
                $attempted += (int) ($result['attempted'] ?? 0);
                $successful += (int) ($result['successful'] ?? 0);
                $failed += (int) ($result['failed'] ?? 0);
                foreach (($result['latencies'] ?? []) as $latency) {
                    if (is_float($latency) || is_int($latency)) {
                        $latencies[] = (float) $latency;
                    }
                }
            }

            $elapsed = (hrtime(true) - $start) / 1_000_000_000;
            cleanupConcurrentBenchmark($database, $barrier);

            return [
                'attempted' => $attempted,
                'successful' => $successful,
                'failed' => $failed,
                'latencies' => $latencies,
                'elapsed' => $elapsed,
                'cpu_seconds' => null,
                'memory_start_mb' => null,
                'memory_end_mb' => null,
                'memory_peak_mb' => null,
                'successful_rpm' => $elapsed > 0.0 ? ($successful / $elapsed) * 60 : 0.0,
            ];
        },
        concurrency: CONCURRENT_WORKERS,
    );
}

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
        $binding = 'warmup-' . $worker . '-' . ($index % 16);
        $code = $otp->generate($binding);
        if (!$otp->verify($binding, $code)) {
            throw new RuntimeException('Concurrent verification warmup failed.');
        }
    }

    file_put_contents($barrier . '.ready.' . $worker, '1');
    while (!is_file($barrier . '.go')) {
        usleep(500);
    }

    $operation = static function () use ($otp, $worker, &$sequence): void {
        $binding = 'worker-' . $worker . '-' . ($sequence % 128);
        $sequence++;
        $code = $otp->generate($binding);
        if (!$otp->verify($binding, $code)) {
            throw new RuntimeException('Concurrent GenericOtp verification was rejected.');
        }
    };
    $measurement = measureOperation($operation, $duration, 20);
    $payload = json_encode([
        'attempted' => $measurement['attempted'],
        'successful' => $measurement['successful'],
        'failed' => $measurement['failed'],
        'latencies' => $measurement['latencies'],
    ], JSON_THROW_ON_ERROR);
    file_put_contents($barrier . '.result.' . $worker, $payload);
}

function cleanupConcurrentBenchmark(string $database, string $barrier): void
{
    $paths = [$barrier . '.go', $database, $database . '-shm', $database . '-wal'];
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
 * @return array<string, mixed>
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
        static function (int $repetition): callable {
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
 */
function measureOperation(callable $operation, float $duration, int $sampleInterval): array
{
    $attempted = 0;
    $successful = 0;
    $failed = 0;
    $latencies = [];
    $usageBefore = getrusage();
    $memoryStart = memory_get_usage(true);
    $start = hrtime(true);
    $deadline = $start + (int) round($duration * 1_000_000_000);

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
        'memory_start_mb' => $memoryStart / 1_048_576,
        'memory_end_mb' => memory_get_usage(true) / 1_048_576,
        'memory_peak_mb' => memory_get_peak_usage(true) / 1_048_576,
        'successful_rpm' => $elapsed > 0.0 ? ($successful / $elapsed) * 60 : 0.0,
    ];
}

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
 * @return array<string, mixed>
 */
function runColdStartWorkload(string $autoload, int $repetitions): array
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
            'stability_spread_limit_percent' => COLD_START_STABILITY_SPREAD_PERCENT,
        ],
        $warmupOperations,
        COLD_START_STABILITY_SPREAD_PERCENT,
        static function (int $repetition) use ($autoload, $warmupOperations): array {
            unset($repetition);
            for ($index = 0; $index < $warmupOperations; $index++) {
                runColdStartOperation($autoload);
            }

            $start = hrtime(true);
            $successful = 0;
            $failed = 0;
            $latencies = [];
            for ($index = 0; $index < COLD_START_OPERATIONS; $index++) {
                $before = hrtime(true);
                if (runColdStartOperation($autoload)) {
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
                'cpu_seconds' => null,
                'memory_start_mb' => null,
                'memory_end_mb' => null,
                'memory_peak_mb' => null,
                'successful_rpm' => $elapsed > 0.0 ? ($successful / $elapsed) * 60 : 0.0,
            ];
        },
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
