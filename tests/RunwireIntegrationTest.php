<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

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
use Infocyph\Runwire\Runtime\RequestExecutionPolicy;
use Infocyph\Runwire\RuntimeCapabilities;
use Infocyph\Runwire\RuntimeContext;
use LogicException;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;

final class RunwireIntegrationTest extends TestCase
{
    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('state operations keep the synchronous path when no Runwire context is supplied')]
    public function testStateOperationsKeepTheSynchronousPathWhenNoRunwireContextIsSupplied(): void
    {
        $cache = CacheLayerState::memory();

        expect(CacheLock::advance($cache, 'runwire-none-state', 'runwire-none-lock', 1, null, 'test'))
            ->toBeTrue()
            ->and($cache->get('runwire-none-state'))->toBe(1);
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    #[TestDox('cancelled Runwire requests fail before authentication state mutation')]
    public function testCancelledRunwireRequestsFailBeforeAuthenticationStateMutation(): void
    {
        $cache = CacheLayerState::memory();
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);
        $request->cancel(CancellationReason::HOST_CANCELLED);

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
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    #[TestDox('completed Runwire requests cannot mutate authentication state')]
    public function testCompletedRunwireRequestsCannotMutateAuthenticationState(): void
    {
        $cache = CacheLayerState::memory();
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);
        $request->complete();

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
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('a request rebound after execution-context construction is rejected before backend access')]
    public function testReboundRequestContextIsRejectedBeforeBackendAccess(): void
    {
        $request = RequestContext::standalone();
        $execution = new RunwireExecutionContext($request->runtime(), $request);
        $request->activate(RuntimeContext::standalone(), new RequestExecutionPolicy());

        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->expects($this->never())->method('isFailOpen');
        $cache->expects($this->never())->method('get');
        $cache->expects($this->never())->method('set');

        expect(fn () => CacheLock::advance(
            $cache,
            'rebound-state',
            'rebound-lock',
            1,
            null,
            'test',
            $execution,
        ))->toThrow(LogicException::class, 'different runtime context');
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('cancellation during cache capability discovery is observed before the atomic read')]
    public function testCancellationDuringCapabilityDiscoveryPreventsAtomicRead(): void
    {
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);
        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->never())->method('setIfAbsent');
        $atomic->expects($this->never())->method('compareAndSet');
        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->expects($this->once())->method('atomic')->willReturnCallback(
            static function () use ($request, $atomic): AtomicCacheInterface {
                $request->cancel(CancellationReason::HOST_CANCELLED);

                return $atomic;
            },
        );
        $cache->expects($this->never())->method('get');

        expect(fn () => CacheLock::advance(
            $cache,
            'cancelled-capability-state',
            'cancelled-capability-lock',
            1,
            null,
            'test',
            $execution,
        ))->toThrow(CancelledException::class);
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    #[TestDox('Runwire runtime contexts are process bound for OTP state operations')]
    public function testRunwireRuntimeContextsAreProcessBoundForOTPStateOperations(): void
    {
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
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('stateful OTP APIs forward the supplied Runwire execution context')]
    public function testStatefulOTPAPIsForwardTheSuppliedRunwireExecutionContext(): void
    {
        $cache = CacheLayerState::memory();
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);
        $request->cancel(CancellationReason::HOST_CANCELLED);
        $otp = new GenericOtp($cache, str_repeat('r', 32));

        expect(fn () => $otp->generate('runwire-api', runwire: $execution))
            ->toThrow(CancelledException::class);

        expect($otp->generate('runwire-api'))->toMatch('/\\A\\d{6}\\z/D');
    }

    /**
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineDeadlockException
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineOverflowException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \OverflowException
     * @throws \Throwable
     */
    #[TestDox('cooperative Runwire lock contention uses zero-wait acquisition and leaves no owned tasks')]
    public function testCooperativeRunwireLockContentionUsesZeroWaitAcquisitionAndLeavesNoOwnedTasks(): void
    {
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
                    static function (LockProviderInterface $locks, LockHandle $handle): string {
                        unset($locks, $handle);

                        return 'acquired';
                    },
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
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('synchronous Runwire lock waits are bounded by the request deadline')]
    public function testSynchronousRunwireLockWaitsAreBoundedByTheRequestDeadline(): void
    {
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime, new RequestExecutionPolicy(maxExecutionSeconds: 0.8));
        $execution = new RunwireExecutionContext($runtime, $request);
        $handle = new LockHandle('deadline-lock', 'owner-token', leaseSeconds: 30.0);
        $locks = $this->createMock(LockProviderInterface::class);
        $locks->expects($this->once())
            ->method('acquire')
            ->willReturnCallback(static function (string $key, float $waitSeconds, float $leaseSeconds) use ($handle): LockHandle {
                expect($key)->toBe('deadline-lock')
                    ->and($waitSeconds)->toBeGreaterThan(0.0)
                    ->and($waitSeconds)->toBeLessThanOrEqual(0.8)
                    ->and($leaseSeconds)->toBe(30.0);

                return $handle;
            });
        $locks->expects($this->once())->method('release')->with($handle);

        $cache = $this->createMock(AuthenticationStateCacheInterface::class);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('authenticationStateLock')->willReturn($locks);

        CacheLock::synchronized(
            $cache,
            'deadline-lock',
            static function (LockProviderInterface $acquiredLocks, LockHandle $acquiredHandle) use ($locks, $handle): void {
                expect($acquiredLocks)->toBe($locks)
                    ->and($acquiredHandle)->toBe($handle);
            },
            $execution,
        );
    }

    /**
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('request cancellation interrupts cooperative lock waiting')]
    public function testRequestCancellationInterruptsCooperativeLockWaiting(): void
    {
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
                    static function (LockProviderInterface $locks, LockHandle $handle): bool {
                        unset($locks, $handle);

                        return true;
                    },
                    $execution,
                );
            },
        ))->toThrow(CancelledException::class);

        $diagnostics = $coroutines->diagnostics();
        expect($diagnostics->activeTasks)->toBe(0)
            ->and($diagnostics->requestScopesActive)->toBe(0);
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('cancellation after lock acquisition prevents the following state mutation and still releases the lock')]
    public function testCancellationAfterLockAcquisitionPreventsTheFollowingStateMutationAndStillReleasesTheLock(): void
    {
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
            static function (mixed $stored): array {
                unset($stored);

                return ['result' => true, 'replacement' => 1];
            },
            $execution,
        ))->toThrow(CancelledException::class);
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException
     * @throws \Throwable
     */
    #[TestDox('a committed atomic mutation is not reclassified by cancellation raised during the commit')]
    public function testACommittedAtomicMutationIsNotReclassifiedByCancellationRaisedDuringTheCommit(): void
    {
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
    }

    /**
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineDeadlockException
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineOverflowException
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \OverflowException
     * @throws \Throwable
     */
    #[TestDox('missing coroutine capability preserves the ordinary lock-provider wait contract')]
    public function testMissingCoroutineCapabilityPreservesTheOrdinaryLockProviderWaitContract(): void
    {
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
                    static function (LockProviderInterface $locks, LockHandle $handle): string {
                        unset($locks, $handle);

                        return 'blocking';
                    },
                    $execution,
                );
            },
        );

        expect($result)->toBe('blocking');
    }

    /**
     * @throws \Infocyph\CacheLayer\Exceptions\CacheInvalidArgumentException
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineDeadlockException
     * @throws \Infocyph\Runwire\Coroutine\Exception\CoroutineOverflowException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \OverflowException
     * @throws \Throwable
     */
    #[TestDox('interleaved request contexts remain isolated and OTP never binds the CacheLayer global runtime')]
    public function testInterleavedRequestContextsRemainIsolatedAndOTPNeverBindsTheCacheLayerGlobalRuntime(): void
    {
        RunwireIntegration::release();

        $capabilities = new RuntimeCapabilities(
            driver: RuntimeDriver::NATIVE,
            runwireLoopAvailable: true,
            supportsRunwireCoroutines: true,
        );
        $runtime = RuntimeContext::fromCapabilities($capabilities, 'otp-test', generation: 1, concurrent: true);
        $cancelledRequest = RequestContext::create($runtime, requestId: 'cancelled-request');
        $liveRequest = RequestContext::create($runtime, requestId: 'live-request');
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
            $cancelledRequest->cancel(CancellationReason::HOST_CANCELLED);
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
            ->and($result[2]->request)->toBe($liveRequest)
            ->and(RunwireIntegration::runtime())->toBeNull();
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('atomic monotonic advance checks Runwire cancellation again after the state read')]
    public function testAtomicMonotonicAdvanceChecksRunwireCancellationAgainAfterTheStateRead(): void
    {
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->never())->method('setIfAbsent');
        $atomic->expects($this->never())->method('compareAndSet');

        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->method('authenticationStateLock')->willReturn(null);
        $cache->expects($this->once())
            ->method('get')
            ->with('cancelled-advance')
            ->willReturnCallback(function () use ($request): null {
                $request->cancel(CancellationReason::HOST_CANCELLED);

                return null;
            });

        expect(fn () => CacheLock::advance(
            $cache,
            'cancelled-advance',
            'unused-lock',
            1,
            null,
            'test',
            $execution,
        ))->toThrow(CancelledException::class);
    }

    /**
     * @throws \Infocyph\Runwire\Exception\CancelledException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    #[TestDox('atomic whole-record transition checks Runwire cancellation again after the state read')]
    public function testAtomicWholeRecordTransitionChecksRunwireCancellationAgainAfterTheStateRead(): void
    {
        $runtime = RuntimeContext::standalone();
        $request = RequestContext::create($runtime);
        $execution = new RunwireExecutionContext($runtime, $request);
        $stored = ['v' => 1, 'remaining' => 2];

        $atomic = $this->createMock(AtomicCacheInterface::class);
        $atomic->expects($this->never())->method('setIfAbsent');
        $atomic->expects($this->never())->method('compareAndSet');

        $cache = $this->createMockForIntersectionOfInterfaces([
            AuthenticationStateCacheInterface::class,
            AtomicCacheProviderInterface::class,
        ]);
        $cache->method('isFailOpen')->willReturn(false);
        $cache->method('hasPayloadIntegrity')->willReturn(true);
        $cache->method('isAuthoritative')->willReturn(true);
        $cache->method('atomic')->willReturn($atomic);
        $cache->method('authenticationStateLock')->willReturn(null);
        $cache->expects($this->once())
            ->method('get')
            ->with('cancelled-transition')
            ->willReturnCallback(function () use ($request, $stored): array {
                $request->cancel(CancellationReason::HOST_CANCELLED);

                return $stored;
            });

        expect(fn () => CacheLock::transition(
            $cache,
            'cancelled-transition',
            'unused-lock',
            'test',
            static function (mixed $current): array {
                unset($current);

                return [
                    'result' => true,
                    'replacement' => ['v' => 1, 'remaining' => 1],
                    'ttl' => 30,
                ];
            },
            $execution,
        ))->toThrow(CancelledException::class);
    }
}
