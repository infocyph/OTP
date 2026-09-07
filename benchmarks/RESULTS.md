# OTP benchmark results

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

No synthetic 6.1 improvement percentage is recorded in this file. Release
numbers must come from an actual successful benchmark run, with PHP version and
environment recorded alongside the result. Stateful TOTP/HOTP/OCRA subjects in
`OtpBench.php` now naturally exercise CacheLayer 3.3 atomics when their selected
backend exposes them, while `GenericOtp` remains the lock-path control.

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
