<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use Infocyph\OTP\Benchmarks\AotpGridBench;
use Infocyph\OTP\Benchmarks\CacheLayer33ReplayBench;
use Infocyph\OTP\Benchmarks\OtpBench;
use Infocyph\OTP\Benchmarks\PasskeyMobileBench;
use PhpBench\Attributes\BeforeMethods;
use ReflectionClass;
use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * @return array<array-key, mixed>
 * @throws \RuntimeException
 */
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
        $process->run();
        if ($workload !== 'sustained' && !$process->isSuccessful()) {
            throw new \Symfony\Component\Process\Exception\ProcessFailedException($process);
        }
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
            $latency = benchmarkResultArray($result['latency_ms'] ?? null);
            $p99 = $latency['p99'] ?? null;
            $peak = $memory['peak_mb'] ?? null;
            $growth = $memory['growth_mb'] ?? null;
            if (!is_numeric($p99) || !is_numeric($peak) || !is_numeric($growth)) {
                throw new RuntimeException('Missing sustained benchmark budget measurements.');
            }
            $withinBudget = (float) $p99 <= 1.0 && (float) $peak <= 64.0 && (float) $growth <= 8.0;
            expect($memory['average_mb'])->toBeGreaterThan(0)
                ->and($growth)->toBeGreaterThanOrEqual(0)
                ->and($metadata['p99_latency_budget_ms'])->toEqual(1.0)
                ->and($metadata['peak_memory_budget_mb'])->toEqual(64.0)
                ->and($metadata['memory_growth_budget_mb'])->toEqual(8.0)
                ->and($process->isSuccessful())->toBe($withinBudget);
            if (!$withinBudget) {
                expect($process->getErrorOutput())->toContain('Sustained benchmark exceeded the absolute');
            }
        }
    } finally {
        if (is_file($output)) {
            unlink($output);
        }
    }
})->with(['sustained', 'concurrent-verify', 'cold-start']);

test('benchmark fixtures remain discoverable and executable after explicit reset', function (): void {
    $aotp = new AotpGridBench();
    $replay = new CacheLayer33ReplayBench();
    $otp = new OtpBench();
    $passkey = new PasskeyMobileBench();
    $suites = [
        [$aotp, [
            $aotp->benchAotpRoundTrip(...),
            $aotp->benchAotpSign(...),
            $aotp->benchGridRespond(...),
            $aotp->benchGridRoundTrip(...),
        ]],
        [$replay, [
            $replay->benchAtomicCompareAndSet(...),
            $replay->benchAtomicMonotonicAdvance(...),
            $replay->benchAtomicOneTimeClaim(...),
            $replay->benchAtomicSetIfAbsent(...),
            $replay->benchLockFallbackMonotonicAdvance(...),
            $replay->benchLockFallbackOneTimeClaim(...),
        ]],
        [$otp, [
            $otp->benchCacheLayerLockRoundTrip(...),
            $otp->benchCacheLayerStateRoundTrip(...),
            $otp->benchCooperativeLockContention(...),
            $otp->benchGenericOtpConstruction(...),
            $otp->benchGenericOtpGenerate(...),
            $otp->benchGenericOtpGenerateWithRunwire(...),
            $otp->benchGenericOtpVerify(...),
            $otp->benchGenericOtpVerifyExhausted(...),
            $otp->benchGenericOtpVerifyFailedAttempt(...),
            $otp->benchGenericOtpVerifyMalformed(...),
            $otp->benchGenericOtpVerifyMissing(...),
            $otp->benchHotpGenerate(...),
            $otp->benchHotpReplayAccepted(...),
            $otp->benchHotpVerify(...),
            $otp->benchHotpVerifyInvalid(...),
            $otp->benchHotpVerifyLookAhead0(...),
            $otp->benchHotpVerifyLookAhead100(...),
            $otp->benchHotpVerifyLookAhead25(...),
            $otp->benchHotpVerifyReplay(...),
            $otp->benchOcraChallengeConsume(...),
            $otp->benchOcraGenerate(...),
            $otp->benchOcraGenerateChallenge(...),
            $otp->benchOcraGenerateCounter(...),
            $otp->benchOcraGenerateFullHmac(...),
            $otp->benchOcraGenerateMutual(...),
            $otp->benchOcraGeneratePin(...),
            $otp->benchOcraGenerateSession(...),
            $otp->benchOcraGenerateTime(...),
            $otp->benchOcraVerify(...),
            $otp->benchOcraVerifyInvalid(...),
            $otp->benchProvisioningEnrollmentPayload(...),
            $otp->benchProvisioningSvgRender(...),
            $otp->benchProvisioningUriBuild(...),
            $otp->benchProvisioningUriParse(...),
            $otp->benchRecoveryConsume(...),
            $otp->benchRecoveryConsumeInvalid(...),
            $otp->benchRecoveryGenerate(...),
            $otp->benchRecoveryGenerate100(...),
            $otp->benchSecretCanonicalValidation(...),
            $otp->benchSecretDecode(...),
            $otp->benchSecretGeneration(...),
            $otp->benchSecretNormalize(...),
            $otp->benchTotpGenerate(...),
            $otp->benchTotpGenerateSha1(...),
            $otp->benchTotpGenerateSha256(...),
            $otp->benchTotpGenerateSha512(...),
            $otp->benchTotpVerify(...),
            $otp->benchTotpVerifyFuture5(...),
            $otp->benchTotpVerifyFuture50(...),
            $otp->benchTotpVerifyInvalid(...),
            $otp->benchTotpVerifyMalformed(...),
            $otp->benchTotpVerifyPast5(...),
            $otp->benchTotpVerifyPast50(...),
            $otp->benchTotpVerifyReplayAccepted(...),
            $otp->benchTotpVerifyReplayRejected(...),
            $otp->benchTotpVerifyWindow0(...),
        ]],
        [$passkey, [
            $passkey->benchMobileOtpGenerate(...),
            $passkey->benchMobileOtpVerify(...),
            $passkey->benchPasskeyBeginAuthentication(...),
            $passkey->benchPasskeyBeginRegistration(...),
        ]],
    ];
    foreach ($suites as [$benchmark, $subjects]) {
        $reflection = new ReflectionClass($benchmark);
        expect($reflection->getAttributes(BeforeMethods::class))->toHaveCount(1);
        foreach ($subjects as $subject) {
            $benchmark->setUp();
            $subject();
        }
    }
});
