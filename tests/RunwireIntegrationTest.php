<?php

declare(strict_types=1);

use Infocyph\CacheLayer\Cache\AtomicCacheInterface;
use Infocyph\CacheLayer\Cache\AtomicCacheProviderInterface;
use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\CacheLayer\Cache\Lock\LockHandle;
use Infocyph\CacheLayer\Cache\Lock\LockProviderInterface;
use Infocyph\CacheLayer\Integration\Runwire\RunwireExecutionContext;
use Infocyph\CacheLayer\Integration\Runwire\RunwireIntegration;
use Infocyph\OTP\GenericOtp;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Tests\Support\CacheLayerState;
use Infocyph\Runwire\Coroutine\CoroutineRuntime;
use Infocyph\Runwire\Coroutine\CoroutineScope;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\Runtime\Enum\RuntimeDriver;
use Infocyph\Runwire\RuntimeCapabilities;
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

test('cooperative Runwire lock contention uses zero-wait acquisition and leaves no owned tasks', function () {
    $capabilities = new RuntimeCapabilities(
        driver: RuntimeDriver::NATIVE,
        runwireLoopAvailable: true,
        supportsRunwireCoroutines: true,
    );
    $runtime = RuntimeContext::fromCapabilities($capabilities, 'otp-test', generation: 1, concurrent: true);
    $request = RequestContext::create($runtime);
    $coroutines = new CoroutineRuntime();
    $handle = new LockHandle('cooperative-lock', 'owner-token', leaseSeconds: 30.0);
    $waits = [];
    $attempt = 0;

    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->exactly(2))
        ->method('acquire')
        ->willReturnCallback(function (string $key, float $waitSeconds, float $leaseSeconds) use (
            &$attempt,
            &$waits,
            $handle,
        ): ?LockHandle {
            expect($key)->toBe('cooperative-lock')
                ->and($leaseSeconds)->toBe(30.0);
            $waits[] = $waitSeconds;
            $attempt++;

            return $attempt === 2 ? $handle : null;
        });
    $locks->expects($this->once())->method('release')->with($handle);

    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn($locks);

    $result = $coroutines->runRequest(
        $request,
        function (CoroutineScope $scope) use ($runtime, $request, $cache): string {
            $execution = new RunwireExecutionContext($runtime, $request, $scope);

            return CacheLock::synchronized(
                $cache,
                'cooperative-lock',
                static fn(LockProviderInterface $locks, LockHandle $handle): string => 'acquired',
                $execution,
            );
        },
    );
    $diagnostics = $coroutines->diagnostics();

    expect($result)->toBe('acquired')
        ->and($waits)->toBe([0.0, 0.0])
        ->and($diagnostics->activeTasks)->toBe(0)
        ->and($diagnostics->requestScopesActive)->toBe(0)
        ->and($diagnostics->backgroundTasksActive)->toBe(0);
});

test('request cancellation interrupts cooperative lock waiting', function () {
    $capabilities = new RuntimeCapabilities(
        driver: RuntimeDriver::NATIVE,
        runwireLoopAvailable: true,
        supportsRunwireCoroutines: true,
    );
    $runtime = RuntimeContext::fromCapabilities($capabilities, 'otp-test', generation: 1, concurrent: true);
    $request = RequestContext::create($runtime);
    $coroutines = new CoroutineRuntime();

    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->atLeastOnce())
        ->method('acquire')
        ->with('cancelled-lock', 0.0, 30.0)
        ->willReturn(null);
    $locks->expects($this->never())->method('release');

    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn($locks);

    expect(fn () => $coroutines->runRequest(
        $request,
        function (CoroutineScope $scope) use ($runtime, $request, $cache): void {
            $execution = new RunwireExecutionContext($runtime, $request, $scope);
            $scope->spawn(function () use ($scope, $request): void {
                $scope->sleep(0.001);
                $request->cancel(CancellationReason::HOST_CANCELLED);
            });

            CacheLock::synchronized(
                $cache,
                'cancelled-lock',
                static fn(LockProviderInterface $locks, LockHandle $handle): bool => true,
                $execution,
            );
        },
    ))->toThrow(CancelledException::class);

    $diagnostics = $coroutines->diagnostics();
    expect($diagnostics->activeTasks)->toBe(0)
        ->and($diagnostics->requestScopesActive)->toBe(0);
});

test('cancellation after lock acquisition prevents the following state mutation and still releases the lock', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $execution = new RunwireExecutionContext($runtime, $request);
    $handle = new LockHandle('mutation-lock', 'owner-token', leaseSeconds: 30.0);

    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->once())->method('acquire')->with('mutation-lock', 1.0, 30.0)->willReturn($handle);
    $locks->expects($this->once())->method('release')->with($handle);

    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn($locks);
    $cache->expects($this->once())
        ->method('get')
        ->with('mutation-state')
        ->willReturnCallback(function () use ($request): null {
            $request->cancel(CancellationReason::HOST_CANCELLED);

            return null;
        });
    $cache->expects($this->never())->method('set');
    $cache->expects($this->never())->method('delete');

    expect(fn () => CacheLock::transition(
        $cache,
        'mutation-state',
        'mutation-lock',
        'test',
        static fn(mixed $stored): array => ['result' => true, 'replacement' => 1],
        $execution,
    ))->toThrow(CancelledException::class);
});

test('a committed atomic mutation is not reclassified by cancellation raised during the commit', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $execution = new RunwireExecutionContext($runtime, $request);

    $atomic = $this->createMock(AtomicCacheInterface::class);
    $atomic->expects($this->once())
        ->method('setIfAbsent')
        ->with('committed-state', 1, null)
        ->willReturnCallback(function () use ($request): bool {
            $request->cancel(CancellationReason::HOST_CANCELLED);

            return true;
        });

    $cache = $this->createMockForIntersectionOfInterfaces([
        AuthenticationStateCacheInterface::class,
        AtomicCacheProviderInterface::class,
    ]);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('atomic')->willReturn($atomic);
    $cache->expects($this->once())->method('get')->with('committed-state')->willReturn(null);

    expect(CacheLock::advance(
        $cache,
        'committed-state',
        'unused-lock',
        1,
        null,
        'test',
        $execution,
    ))->toBeTrue()
        ->and($request->cancelled())->toBeTrue();
});

test('missing coroutine capability preserves the ordinary lock-provider wait contract', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $coroutines = new CoroutineRuntime();
    $handle = new LockHandle('blocking-lock', 'owner-token', leaseSeconds: 30.0);

    $locks = $this->createMock(LockProviderInterface::class);
    $locks->expects($this->once())->method('acquire')->with('blocking-lock', 1.0, 30.0)->willReturn($handle);
    $locks->expects($this->once())->method('release')->with($handle);

    $cache = $this->createMock(AuthenticationStateCacheInterface::class);
    $cache->method('isFailOpen')->willReturn(false);
    $cache->method('hasPayloadIntegrity')->willReturn(true);
    $cache->method('isAuthoritative')->willReturn(true);
    $cache->method('authenticationStateLock')->willReturn($locks);

    $result = $coroutines->runRequest(
        $request,
        function (CoroutineScope $scope) use ($runtime, $request, $cache): string {
            $execution = new RunwireExecutionContext($runtime, $request, $scope);

            return CacheLock::synchronized(
                $cache,
                'blocking-lock',
                static fn(LockProviderInterface $locks, LockHandle $handle): string => 'blocking',
                $execution,
            );
        },
    );

    expect($result)->toBe('blocking');
});

test('interleaved request contexts remain isolated and OTP never binds the CacheLayer global runtime', function () {
    RunwireIntegration::release();

    $capabilities = new RuntimeCapabilities(
        driver: RuntimeDriver::NATIVE,
        runwireLoopAvailable: true,
        supportsRunwireCoroutines: true,
    );
    $runtime = RuntimeContext::fromCapabilities($capabilities, 'otp-test', generation: 1, concurrent: true);
    $cancelledRequest = RequestContext::create($runtime, requestId: 'cancelled-request');
    $liveRequest = RequestContext::create($runtime, requestId: 'live-request');
    $cancelledRequest->cancel(CancellationReason::HOST_CANCELLED);
    $coroutines = new CoroutineRuntime();
    $otp = new GenericOtp(CacheLayerState::memory(), str_repeat('w', 32));

    $result = $coroutines->run(function (CoroutineScope $scope) use (
        $runtime,
        $cancelledRequest,
        $liveRequest,
        $otp,
    ): array {
        $cancelled = new RunwireExecutionContext($runtime, $cancelledRequest, $scope);
        $live = new RunwireExecutionContext($runtime, $liveRequest, $scope);
        $cancelledTask = $scope->spawn(function () use ($otp, $cancelled): string {
            try {
                $otp->generate('cancelled-binding', runwire: $cancelled);
            } catch (CancelledException) {
                return 'cancelled';
            }

            return 'unexpected';
        });
        $liveTask = $scope->spawn(
            static fn(): string => $otp->generate('live-binding', runwire: $live),
        );

        return [$cancelledTask->await(), $liveTask->await(), $live];
    });

    expect($result[0])->toBe('cancelled')
        ->and($result[1])->toMatch('/\A\d{6}\z/D')
        ->and($result[2])->toBeInstanceOf(RunwireExecutionContext::class)
        ->and($result[2]->request)->toBe($liveRequest)
        ->and(RunwireIntegration::runtime())->toBeNull();
});
