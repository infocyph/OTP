<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\RuntimeContext;
use LogicException;

test('state operations keep the synchronous path when no Runwire context is supplied', function () {
    $cache = CacheLayerState::memory();

    expect(CacheLock::advance($cache, 'runwire-none-state', 'runwire-none-lock', 1, null, 'test'))
        ->toBeTrue()
        ->and($cache->get('runwire-none-state'))->toBe(1);
});

test('cancelled Runwire requests fail before authentication state mutation', function () {
    $cache = CacheLayerState::memory();
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $request->cancel(CancellationReason::HOST_CANCELLED);
    $execution = new RunwireExecutionContext($runtime, $request);

    expect(fn () => CacheLock::advance(
        $cache,
        'runwire-cancelled-state',
        'runwire-cancelled-lock',
        1,
        null,
        'test',
        $execution,
    ))->toThrow(CancelledException::class)
        ->and($cache->get('runwire-cancelled-state'))->toBeNull();
});

test('completed Runwire requests cannot mutate authentication state', function () {
    $cache = CacheLayerState::memory();
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $request->complete();
    $execution = new RunwireExecutionContext($runtime, $request);

    expect(fn () => CacheLock::advance(
        $cache,
        'runwire-completed-state',
        'runwire-completed-lock',
        1,
        null,
        'test',
        $execution,
    ))->toThrow(LogicException::class, 'Completed Runwire request context')
        ->and($cache->get('runwire-completed-state'))->toBeNull();
});

test('Runwire runtime contexts are process bound for OTP state operations', function () {
    $cache = CacheLayerState::memory();
    $current = RuntimeContext::standalone();
    $runtime = new RuntimeContext(
        driver: $current->driver,
        mode: 'otp-test',
        workerSlot: $current->workerSlot,
        generation: $current->generation,
        pid: $current->pid + 1,
        persistent: $current->persistent,
        concurrent: $current->concurrent,
        ownsListener: $current->ownsListener,
        ownsEventLoop: $current->ownsEventLoop,
        ownsWorkerPool: $current->ownsWorkerPool,
        capabilities: $current->capabilities,
    );
    $execution = new RunwireExecutionContext($runtime);

    expect(fn () => CacheLock::advance(
        $cache,
        'runwire-stale-state',
        'runwire-stale-lock',
        1,
        null,
        'test',
        $execution,
    ))->toThrow(LogicException::class, 'different process')
        ->and($cache->get('runwire-stale-state'))->toBeNull();
});


test('stateful OTP APIs forward the supplied Runwire execution context', function () {
    $cache = CacheLayerState::memory();
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $request->cancel(CancellationReason::HOST_CANCELLED);
    $execution = new RunwireExecutionContext($runtime, $request);
    $otp = new GenericOtp($cache, str_repeat('r', 32));

    expect(fn () => $otp->generate('runwire-api', runwire: $execution))
        ->toThrow(CancelledException::class);

    expect($otp->generate('runwire-api'))->toMatch('/\\A\\d{6}\\z/D');
});
