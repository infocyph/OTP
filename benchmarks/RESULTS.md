# OTP benchmark results

## OTP 7.0 / Runwire cooperative contention snapshot

Batch 9 adds a synthetic one-miss lock provider exercised through a real
``CoroutineRuntime`` request scope. The provider rejects blocking waits, misses
once, yields through the supplied scope, and then acquires successfully.

| Subject | PHP 8.4 | PHP 8.5 |
| --- | ---: | ---: |
| Cooperative lock contention, one forced miss | 6,329 µs | 6,443 µs |
| Generic OTP generate, no context | 115 µs | 135 µs |
| Generic OTP generate, supplied context | 121 µs | 157 µs |

The cooperative contention subject intentionally includes one scheduler sleep of
up to 5 ms, so its ~6.3-6.4 ms CI result is evidence that the cooperative path is
executed and bounded, not a target latency or throughput claim. The ordinary
no-context path remains independently benchmarked and all Batch 9 correctness
and lifecycle gates passed on the same revision.

## OTP 7.0 / optional Runwire Batch 8 snapshot

Recorded on 2026-10-03 from the exact green Batch 8 revision on the same GitHub
Actions class as the pre-Runwire snapshot. Runwire 2.1 was installed for
development coverage. Existing benchmark subjects did not supply a Runwire
context; ``benchGenericOtpGenerateWithRunwire`` supplied the shared
``RunwireExecutionContext`` with a standalone runtime/request and no coroutine
scope.

| Subject | PHP 8.4 | PHP 8.5 |
| --- | ---: | ---: |
| Generic OTP generate, no context | 141 µs | 60 µs |
| Generic OTP generate, supplied context | 140 µs | 66 µs |
| Generic OTP verify, no context | 141 µs | 76 µs |
| GridOTP round trip, no context | 499 µs | 277 µs |
| OTP atomic monotonic advance, no context | 460 µs | 280 µs |
| OTP lock-fallback monotonic advance, no context | 625 µs | 386 µs |
| Passkey begin authentication, no context | 1,796 µs | 1,029 µs |
| Passkey begin registration, no context | 2,376 µs | 1,379 µs |

These CI measurements are single-iteration attribution snapshots and vary
materially between runners; they do not satisfy the plan's stable-host 2% RPM
regression budget. Within the same final jobs, the supplied Generic OTP context
measured 140 vs 141 µs on PHP 8.4 and 66 vs 60 µs on PHP 8.5, with roughly
0.5 KiB additional reported peak memory. Treat those values as evidence that the
path is benchmarked, not as a performance gain or regression conclusion.
Cooperative contention and persistent-runtime measurements belong to Batch 9.

## OTP 7.0 / CacheLayer 4.0 pre-Runwire baseline

Recorded on 2026-10-03 from the green Batch 7 GitHub Actions benchmark lanes on
Ubuntu 24.04 with Xdebug disabled, PHPBench 1.7.0, and CacheLayer 4.0. These
one-iteration CI modes are an attribution snapshot, not a stable throughput or
RPM regression baseline. They are recorded before OTP adds any optional Runwire
execution-context checks.

| Subject | PHP 8.4 | PHP 8.5 |
| --- | ---: | ---: |
| Generic OTP generate | 114 µs | 72 µs |
| Generic OTP verify | 138 µs | 113 µs |
| GridOTP round trip | 522 µs | 252 µs |
| Atomic `setIfAbsent` | 22 µs | 13 µs |
| Atomic CAS | 85 µs | 44 µs |
| OTP atomic monotonic advance | 406 µs | 242 µs |
| OTP lock-fallback monotonic advance | 611 µs | 372 µs |
| OTP atomic one-time claim | 409 µs | 252 µs |
| OTP lock-fallback one-time claim | 579 µs | 352 µs |
| Passkey begin authentication | 1,492 µs | 1,261 µs |
| Passkey begin registration | 2,243 µs | 1,955 µs |

The Batch 8 post-change run must compare the same subjects on the same CI class.
Normal execution with no supplied Runwire context is the primary regression path;
Runwire installed but unused must not alter state semantics.

## OTP 6.1 / CacheLayer 3.3 attribution

OTP 6.1 adds dedicated subjects for CacheLayer 3.3 replay coordination. CI runs
the benchmark suite through the repository `benchmark` Composer script on the
supported PHP matrix. The new subjects separate the conditional primitives from
the OTP replay coordinator:

| Subject | Purpose |
| --- | --- |
| `benchAtomicSetIfAbsent` | Native CacheLayer one-time conditional insertion |
| `benchAtomicCompareAndSet` | Native CacheLayer monotonic CAS |
| `benchAtomicMonotonicAdvance` | OTP monotonic replay coordinator on an atomic-capable memory backend |
| `benchLockFallbackMonotonicAdvance` | OTP monotonic replay coordinator on an authoritative file/lock backend |
| `benchAtomicOneTimeClaim` | OTP one-time replay claim on native atomics |
| `benchLockFallbackOneTimeClaim` | OTP one-time replay claim on coordinated-lock fallback |

The lock-fallback and atomic subjects deliberately use different concrete
backends because CacheLayer does not claim atomic coordination for its file
backend. Their absolute timings therefore attribute complete valid paths; they
must not be presented as a pure lock-vs-CAS micro-operation ratio. Direct
`setIfAbsent` and CAS subjects provide the lower-level atomic cost attribution.

### 6.1 CI attribution snapshot

Recorded on 2026-09-07 from successful GitHub Actions runs on Ubuntu 24.04 with
Xdebug disabled, PHPBench 1.7.0, CacheLayer 3.3, and the repository's one-run
representative CI benchmark configuration. Values below are PHPBench reported
mode times in microseconds. GitHub-hosted runners are not a stable performance
environment, so these numbers document path attribution only and are not a
regression baseline.

| Subject | PHP 8.4.25 | PHP 8.5.10 |
| --- | ---: | ---: |
| Atomic `setIfAbsent` | 16 µs | 18 µs |
| Atomic CAS | 61 µs | 75 µs |
| OTP atomic monotonic advance | 210 µs | 233 µs |
| OTP lock-fallback monotonic advance | 465 µs | 548 µs |
| OTP atomic one-time claim | 200 µs | 250 µs |
| OTP lock-fallback one-time claim | 432 µs | 461 µs |

The atomic path is materially lighter in this representative run, but no
percentage claim is published because the valid atomic and lock-fallback
subjects use different concrete backends and the CI runners are not stable.
Stateful TOTP/HOTP/OCRA subjects in `OtpBench.php` naturally exercise CacheLayer
3.3 atomics when their selected backend exposes them, while `GenericOtp` remains
the lock-path control.

## CacheLayer migration benchmark — OTP 6.0 baseline

Recorded on 2026-08-14 with PHP 8.4.24, PHPBench 1.7.0, no Xdebug, and no
OPcache. The release run used ``composer ic:bench:run`` and completed all 54
subjects with zero failures. A supplementary quick run used 10 revolutions and
3 iterations for repeatable, non-destructive subjects.

These are component microbenchmarks, not application-throughput or RPM claims.
The in-memory CacheLayer backend and filesystem lock isolate library overhead;
production Redis/database latency, persistence, contention, and failover must
be measured in the deployment environment.

### Corrected edge workloads

The subjects below now measure the operation named: Generic OTP failed-attempt
transitions use one revolution so setup creates a fresh finite-attempt record,
HOTP look-ahead codes match at the final searched counter, and TOTP window
codes match at the requested past/future edge. The timing modes are from the
supplementary quick run except the destructive Generic OTP transition, which
is from the full release run and deliberately uses one revolution.

| Subject | Workload | Mode |
| --- | --- | ---: |
| Generic OTP failed attempt | Fresh valid record, wrong code, one decrement | 92.000 µs |
| HOTP look-ahead 0 | Match counter 5 at exact position | 2.079 µs |
| HOTP look-ahead 25 | Match counter 25 from counter 0 | 24.886 µs |
| HOTP look-ahead 100 | Match counter 100 from counter 0 | 105.340 µs |
| TOTP exact | Match current step | 2.194 µs |
| TOTP past 5 | Match final past step | 5.636 µs |
| TOTP past 50 | Match final past step | 37.450 µs |
| TOTP future 5 | Match final future step | 6.242 µs |
| TOTP future 50 | Match final future step | 41.345 µs |

### Security-state diagnostics

| Subject | Mode |
| --- | ---: |
| CacheLayer state set/get round trip | 11.794 µs |
| CacheLayer lock acquire/release round trip | 7.288 µs |
| Generic OTP generate/replace | 34.000 µs |
| Generic OTP successful consume | 92.000 µs |
| Generic OTP exhausted transition | 87.000 µs |
| Generic OTP missing state | 21.000 µs |
| HOTP monotonic first acceptance | 30.000 µs |
| HOTP replay rejection | 56.000 µs |
| TOTP replay first acceptance | 39.000 µs |
| TOTP replay rejection | 69.000 µs |
| OCRA challenge consumption | 76.000 µs |

The stateful figures include authenticated CacheLayer payload handling and the
binding/factor-scoped lock. The former in-memory OTP/replay stores performed
direct array mutations and could not coordinate multiple workers or hosts, so
these figures are not a like-for-like optimization regression. The full raw
suite remains the authoritative release gate; this document highlights the
security-sensitive and corrected worst-case subjects.
