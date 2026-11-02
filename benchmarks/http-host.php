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

$options = getopt('', ['autoload:', 'address:', 'ready-dir:']);
require $options['autoload'];
$readyDirectory = $options['ready-dir'];
$cacheOptions = new CacheOptions(
    integrityKey: str_repeat('i', 32),
    allowClosures: false,
    allowObjects: false,
    failOpen: false,
);
$database = $readyDirectory . '/state.sqlite';
$initializer = Cache::sqlite('otp-http-host', $database, $cacheOptions);
$initializer->set('ready', true, 60);
unset($initializer);
$server = Server::http($options['address'], static function (HttpRequest $request, ResponseWriterInterface $writer): void {
    unset($request, $writer);

    throw new RuntimeException('Worker handler factory was not used.');
})->withWorkers(2)->withWorkerConnectionLimit(256)->withWorkerHandlerFactory(
    static function (WorkerContext $worker) use ($readyDirectory, $database, $cacheOptions): callable {
        unset($worker);
        $cache = Cache::sqlite('otp-http-host', $database, $cacheOptions);
        $otp = new GenericOtp($cache, str_repeat('g', 32), ttlSeconds: 60);
        $ocra = new OCRA('OCRA-1:HOTP-SHA256-6:C-QN08', str_repeat('o', 32));
        $sequence = 0;
        $uri = $ocra->getProvisioningUri('fixture', 'OTP');
        file_put_contents($readyDirectory . '/ready-' . getmypid(), 'ready');

        return static function (HttpRequest $request, ResponseWriterInterface $writer) use (
            $cache,
            $otp,
            $ocra,
            $uri,
            &$sequence,
        ): void {
            $execution = new RunwireExecutionContext($request->context->runtime(), $request->context);
            $binding = 'fixture-' . getmypid() . '-' . ($sequence % 64);
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
                'http-ocra-' . getmypid(),
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
