<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\Cache;
use Infocyph\CacheLayer\Cache\CacheOptions;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\Runwire\Http\Headers;
use Infocyph\Runwire\Http\HttpRequest;
use Infocyph\Runwire\Http\ResponseWriterInterface;
use Infocyph\Runwire\Runtime;
use Infocyph\Runwire\Server;
use Infocyph\Runwire\Supervisor\WorkerContext;

$options = getopt('', ['autoload:', 'address:', 'workload:']);
if ($options === false) {
    throw new RuntimeException('Unable to parse HTTP benchmark arguments.');
}
$autoload = $options['autoload'] ?? null;
$address = $options['address'] ?? null;
$workload = $options['workload'] ?? 'full';
if (!in_array($workload, ['full', 'no-context', 'memory', 'memory-no-context', 'transport'], true)) {
    throw new RuntimeException('Unknown HTTP benchmark workload.');
}
$readyDirectory = getcwd();
if (!is_string($autoload) || !is_file($autoload) || !is_string($address) || !is_string($readyDirectory)) {
    throw new RuntimeException('HTTP benchmark requires valid autoload, address and a private working directory.');
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
$cacheOptions = new CacheOptions(
    integrityKey: str_repeat('i', 32),
    allowClosures: false,
    allowObjects: false,
    failOpen: false,
);
$database = $readyDirectory . '/state.sqlite';
if ($workload === 'full' || $workload === 'no-context') {
    $initializer = Cache::sqlite('otp-http-host', $database, $cacheOptions);
    $initializer->set('ready', true, 60);
    unset($initializer);
}
$server = Server::http($address, static function (HttpRequest $request, ResponseWriterInterface $writer): void {
    unset($request, $writer);

    throw new RuntimeException('Worker handler factory was not used.');
})->withWorkers(2)->withWorkerConnectionLimit(256)->withWorkerHandlerFactory(
    static function (WorkerContext $worker) use ($readyDirectory, $database, $cacheOptions, $workload): callable {
        unset($worker);
        $pid = getmypid();
        if ($pid === false) {
            throw new RuntimeException('Unable to identify HTTP worker.');
        }
        if ($workload === 'transport') {
            file_put_contents($readyDirectory . '/ready-' . $pid, 'ready');

            return static function (HttpRequest $request, ResponseWriterInterface $writer): void {
                unset($request);
                $writer->start(200, Headers::fromArray(['content-type' => 'application/json']));
                $writer->end('{"transport":true}');
            };
        }

        $cache = $workload === 'memory' || $workload === 'memory-no-context'
            ? Cache::memory('otp-http-host', $cacheOptions)
            : Cache::sqlite('otp-http-host', $database, $cacheOptions);
        $withContext = $workload === 'full' || $workload === 'memory';
        $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
        $ocra = new OCRA('OCRA-1:HOTP-SHA256-6:C-QN08', str_repeat('o', 32));
        $sequence = 0;
        $uri = $ocra->getProvisioningUri('fixture', 'OTP');
        file_put_contents($readyDirectory . '/ready-' . $pid, 'ready');

        return static function (HttpRequest $request, ResponseWriterInterface $writer) use (
            $cache,
            $otp,
            $ocra,
            $uri,
            &$sequence,
            $pid,
            $withContext,
        ): void {
            $execution = $withContext
                ? new RunwireExecutionContext($request->context->runtime(), $request->context)
                : null;
            $binding = 'fixture-' . $pid . '-' . ($sequence % 64);
            $sequence++;
            $code = $otp->generate($binding, $execution);
            $accepted = $otp->verify($binding, $code, $execution);
            $replayRejected = !$otp->verify($binding, $code, $execution);
            $response = $ocra->generate('12345678', counter: $sequence);
            $ocraAccepted = $ocra->verifyWithResult(
                $response,
                '12345678',
                $sequence,
                null,
                null,
                null,
                null,
                $cache,
                'http-ocra-' . $pid,
                null,
                $execution,
            )->matched;
            $parsed = ProvisioningUriParser::parse($uri);
            if (!$accepted || !$replayRejected || !$ocraAccepted || $parsed->type !== 'ocra') {
                throw new RuntimeException('HTTP benchmark authentication validation failed.');
            }
            $writer->start(200, Headers::fromArray(['content-type' => 'application/json']));
            $writer->end('{"accepted":true,"replay_rejected":true,"ocra":true,"provisioning":true}');
        };
    },
);
Runtime::create()->listen($server)->run();
