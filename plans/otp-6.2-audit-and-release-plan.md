# OTP audit, hardening, and optional Runwire integration plan

Date: 2026-10-03. Status: audit complete; implementation and release gates pending.

## Decision

Deliver **one consolidated release, targeting 7.0.0**, containing security/correctness hardening, a direct CacheLayer 4.0 dependency floor, optional explicitly passed Runwire 2.1 context, documentation, and all required verification. Implementation can proceed in ordered workstreams, but they share one release candidate, changelog, acceptance decision, and tag. Do not publish an intermediate hardening release.

Keep PHP `^8.4` / 64-bit requirements. Raise CacheLayer directly to `^4.0`; OTP 7.0 does not support CacheLayer 3.x. Keep Runwire optional. This dependency-floor break is carried by the same consolidated **7.0.0** candidate with explicit CacheLayer 3.x → 4.x migration and rollback guidance rather than a split release.

This document follows `vendor/infocyph/phpforge/resources/engineering-principles.md`: security and protocol correctness first; smallest changes in existing owners; explicit lifecycle and persistence ownership; no speculative framework layers; measured performance; no weakened quality gates. No production code or Composer dependencies were changed during this audit.

## Evidence and limits

Reviewed all 36 production PHP files: Generic OTP, HOTP, TOTP, OCRA, AOTP, GridOTP, MobileOTP, Passkey, recovery codes, storage contract, results, value objects, provisioning, rotation, encoding, arithmetic, and state coordination. Inspected tests, relevant security/integration documentation, benchmarks, Composer metadata, and CI. Used the existing graph for navigation and current source for conclusions.

| Item | Observed baseline |
| --- | --- |
| OTP revision | Tag `6.1`, commit `c7faf376b96611638e7bc0da6cd081496768d34f` |
| Normal host | PHP 8.5.4 CLI, 64-bit, NTS; Composer 2.10.3 |
| Installed dependencies | CacheLayer 3.4, WebAuthn 5.3.9, PHPForge dev-main `18917f3`, BaconQrCode 3.1.1, constant_time_encoding 3.1.3 |
| PHPForge setup | `ic:doctor` healthy; config resolution and active configurations inspected |
| Composer metadata | `composer validate --strict` passed |
| Detailed quality suite | `composer ic:tests:details` exited 1: skipper found three explicit skip directives |
| Pest baseline | 145 passed, 4 deprecated, 7 skipped; 716 assertions |
| Host socket rerun | `composer ic:test:code` with local socket access produced the same counts; Redis service availability remains unresolved, not just sandbox isolation |
| Other detailed checks | Normalize, syntax, references, duplicates, comments, Pint, PHPCS, Deptrac, PHPStan, Psalm, and Rector dry-run passed |
| Live Composer audit | No published advisories for locked packages; exit 1 because `doctrine/annotations` is abandoned; it is required by development dependency PHPBench 1.7.0 |
| Benchmark smoke | `composer benchmark` completed 68 subjects; one iteration/revolution per reported subject; not a stable performance baseline or RPM result |
| CacheLayer source inspected | Clean local checkout at tag `4.0`, commit `58ae96dfe14ee45a528247c00c6a3d727160f833` |
| Runwire source inspected | Clean local checkout at tag `2.1`, commit `178308361772d4e995040a8ab84d4df876579078` |

An exploratory CacheLayer 4 class-loader substitution ran the existing tests: 144 passed, 4 deprecated, 7 skipped, and one architecture-tool error (`ObjectDescriptionBase::$stmts` uninitialized). This was not a clean Composer installation: it retained the original dependency tree and Composer file autoloading. It provides limited behavioral evidence and **does not establish CacheLayer 4 compatibility**. Resolve that experiment through clean installations, not by disabling the architecture test.

The initial direct Pest invocation without explicit configuration failed config discovery (`Could not read XML from file "--cache-directory"`); the repository Composer command worked. Use repository tooling for reproducible runs.

No PHP 8.4 run, clean dependency matrix, live Redis concurrency acceptance, successful WebAuthn ceremony fixture, Runwire integration, persistent-worker soak, or final-revision CI was completed. No claim of vulnerability-free code or release readiness follows from the passing checks.

Session evidence is in `/tmp/otp-audit-quality.log`, `/tmp/otp-audit-pest-host.log`, `/tmp/otp-audit-cachelayer4.log`, `/tmp/otp-audit-probes.php`, and `/tmp/otp-audit-benchmark.json`. These temporary files are supplementary; the findings and required regressions below are the durable record.

## Findings and remediation

Priorities indicate engineering urgency, not assigned CVSS scores or published advisories.

### F1 — P1: secret-bearing service objects expose secrets in debug output

Locations: private secret/key properties in `src/HOTP.php`, `TOTP.php`, `OCRA.php`, `GenericOtp.php`, `GridOTP.php`, `MobileOTP.php`, and `RecoveryCodes.php`; existing redaction tests are in `tests/SensitiveOutputTest.php`.

Confirmed: capturing `var_dump()` of each of these seven objects exposed the synthetic secret or HMAC key used to construct it. Private visibility and constructor `SensitiveParameter` attributes do not redact object dumps. A dump of a service may also recursively expose its cache/store collaborators. Result/value-object debug redaction already exists, but service redaction does not.

Impact: conditional credential disclosure through debugging, exception diagnostics, or logs that dump objects; this is not evidence of an unauthenticated remote read by itself.

Required changes:

- Add narrowly scoped `__debugInfo()` methods in existing secret-bearing owners. Emit safe configuration and redacted placeholders; do not dump cache/store/serializer object graphs.
- Review Passkey and AOTP service diagnostics for indirect cached-state exposure even where the service's own key is public.
- Audit sensitive arguments through internal exception stack frames, not only public entry points.
- Test actual `var_dump()` and `print_r()` output with unique sentinel values, including nested objects and representative thrown exceptions. Keep existing value-object tests.
- Document that PHP serialization, `var_export()`, reflection, and arbitrary application logging are separate boundaries; do not promise universal redaction or silently change persistence formats.

Acceptance: no tested diagnostic output contains factor secrets, HMAC keys, private keys, PINs, live codes, or embedded cache contents. Normal arithmetic and verification results remain unchanged.

### F2 — P1: malformed WebAuthn payloads escape the documented failure contract

Locations: `src/Passkey.php:405` (`deserializeCredential`) and its callers in extraction and ceremony completion; dependency `PublicKeyCredentialDenormalizer`.

Confirmed against WebAuthn 5.3.9 with an active authentication ceremony:

| Credential JSON | Actual outcome |
| --- | --- |
| `null` | `TypeError` |
| `[]` | structured `Malformed` |
| Object with `id: "!"`, `rawId: "!"`, type `public-key`, empty response | `RangeException` |
| Object with `id: "YQ"`, `rawId: "Yg"`, type `public-key`, empty response | `Webauthn\Exception\InvalidDataException` |

The current catch covers only Symfony serializer exceptions. InvalidDataException also retains the supplied data, making unredacted exception logging problematic. Existing tests use `{}` and do not exercise these shapes.

Required changes:

- Bound and validate top-level JSON and the field shapes needed before invoking the dependency's denormalizer. Include null, scalar, list, wrong field types, missing fields, malformed encodings, depth, and size boundaries.
- Convert documented input/encoding exceptions at the **untrusted browser-payload boundary** into `Malformed`. Preserve `extractCredentialId()`'s documented invalid-input exception contract with a safe message.
- Do not blanket-catch all `Throwable` around verification. Corrupt persisted records, backend failures, cancellation, and programming errors must remain distinguishable infrastructure/configuration failures.
- Test that rejected browser payloads never consume the ceremony and that diagnostics do not expose raw payloads.
- Remove the 5.3 RP-name deprecation at `Passkey.php:127` using the installed dependency's supported empty-name behavior; verify serialized `rp.name` remains correct.

Add real valid registration/assertion fixtures, duplicate completion races, wrong RP/origin, missing user verification, wrong user handle, stale counters, and revoked-credential host examples. Current `PasskeyTest.php` has no successful cryptographic registration/assertion round trip; manually setting a consumed marker does not test successful consumption.

Acceptance: malformed-input corpus yields documented failure results, valid fixtures succeed once, replay fails, and supported WebAuthn versions produce no project-triggered deprecations.

### F3 — P2: end-of-string validation accepts trailing newlines

Locations: `src/OCRA.php:370`, `src/ValueObjects/OcraSuite.php:11`, `src/RecoveryCodes.php:146`.

Confirmed: an OCRA suite ending in LF is accepted; numeric and alphanumeric challenges ending in LF are accepted. PHP regex `$` can match before a final newline. The suite retains that newline in the HMAC input, and numeric conversion receives a character outside its assumed domain.

Confirmed: `RecoveryCodes::generate(..., length: 40, groupSize: 0, characterSet: "A\n")` accepts the alphabet and counts LF toward entropy. In the probe, all ten returned codes were unusable by `consume()`.

Required changes:

- Use absolute anchors (`\A` / `\z`) for strict protocol fields and alphabets; preserve intentional user-facing recovery-code normalization.
- Enforce byte/collection bounds before costly decoding or iteration where the public contract already defines a limit.
- Test LF, CRLF, NUL, Unicode separators, overlong input, and every OCRA challenge format. Keep all existing RFC vectors and mutual/signature modes.
- Test that every generated code from every supported alphabet can be consumed exactly once. Entropy calculations must count only actually usable symbols.

Acceptance: malformed protocol input is rejected deterministically; valid vectors and valid custom alphabets retain their outputs and behavior.

### F4 — P1 policy hardening: GridOTP response length is not guaranteed guessing entropy

Locations: `src/GridOTP.php:177` and `respond()`; `docs/guides/grid-otp.rst`, `docs/guides/security.rst`.

Confirmed: `AAAAAAAA` is an accepted enrolled secret. A challenge with six distinct positions produces the same response digit six times. That response space has at most ten candidates, not one million. Secret generation is random, but callers may supply weak secrets; repeated symbols also correlate response positions.

Required work:

- Document effective response entropy and the existing observation/relay limitations; never equate six requested positions with six independent random digits.
- Design and test a secure enrollment policy based on symbol diversity and challenge selection, including generated secrets. Do not arbitrarily claim that one diversity threshold proves a security level.
- Quantify worst-case and representative online success probability with repeated symbols and balanced grid collisions; preserve strict attempt/rate limits.
- Provide an inventory/re-enrollment migration for existing weak factors. Do not silently regenerate their secret or lock users out during a dependency update.
- Include the advisory/documentation, regression evidence, and selected enrollment policy in the consolidated candidate. Preserve compatibility through an explicit opt-in/deprecation path where safe; if required enforcement is incompatible, version the same consolidated release as a major and include its migration.

Acceptance: the release accurately describes the risk, tests it, and provides a concrete migration path; any enforced policy must meet a documented guessing budget. This is a custom-protocol review item, not a claim that GridOTP is equivalent to WebAuthn.

Implementation decision (2026-10-03): keep existing factors compatible in 7.0 while making the secure path explicit. Generated secrets guarantee enough distinct symbols for every supported challenge size; challenge selection uses distinct secret symbols whenever the enrolled secret permits it. ``GridOTP::hasSufficientDiversity()`` supports inventory, and trailing ``enforceDiversity`` provides opt-in enforcement for new/re-enrolled factors. Existing insufficient-diversity factors continue through the legacy position-selection path until re-enrollment; they are not silently regenerated or locked out.

### F5 — P1 release gate: skipped tests and dependency hygiene

Locations: `tests/AOTPTest.php:231`, `tests/GridOTPTest.php:117`, `tests/RedisConcurrencyTest.php:14`, `.github/workflows/security-standards.yml`, Composer development dependency tree.

The installed skipper rejects three explicit `markTestSkipped()` call sites even when some branches do not execute. Seven Redis cases still skipped after a host socket rerun. CI already declares SQLite/Redis and PHP 8.4/8.5 lowest/stable dependencies, so the intended matrix is appropriate but is not current passing evidence.

Required work:

- Provision required test prerequisites and make required matrix failures explicit. Remove skip directives by correcting the test/prerequisite workflow, not by deleting tests, adding exclusions, or disabling skipper.
- Keep optional-package absence tests in separate clean consumer installations so the runtime package remains optional without skipping release coverage.
- Resolve the PHPBench → abandoned doctrine/annotations chain through compatible upstream tooling/dependency changes. Do not disable auditing or relabel abandonment as a CVE. If upstream prevents resolution, record the blocker and hold the affected release gate.
- Keep stable runtime constraints and validate a clean production `--no-dev` install.

### F6 — targeted concurrency review required before stronger runtime claims

Locations: `src/Support/CacheLock.php:98` and all refresh-then-set/delete paths, especially GenericOtp, GridOTP, and Passkey.

The code refreshes a 30-second lease and then performs a separate mutation. This detects loss **before** refresh, but does not itself fence a process paused between refresh and mutation. A leased distributed backend could admit another owner before the first resumes. This is a source-level risk; a real-backend stale-owner exploit was not reproduced in this audit.

Required acceptance work:

- Add deterministic stale-owner fault injection and real Redis tests for suspension after refresh, lease expiry, replacement issuance, attempt decrements, and successful consumption.
- If stale mutations remain possible, use backend-atomic conditional transitions/fencing or a provider contract whose ownership covers the actual mutation. Merely increasing the lease or scheduling renewals is not proof of safety.
- Generic/Grid/Passkey state is multi-field, but CacheLayer CAS accepts `mixed` values; evaluate whole-record CAS with explicit live/consumed/replaced states rather than assuming arrays require locks. Issuance/replacement/deletion and ABA hazards must be solved together, not one method at a time.
- Retain fail-closed integrity/authority checks, bounded contention, current key-generation isolation, and the prohibition on fallback after an unknown mutation outcome.
- Keep this a focused state-safety change. Escalate release/version scope only if a new persistence contract or migration is actually required.

## CacheLayer 4.0 adoption

The public authentication-state and atomic interfaces inspected in installed 3.4 and tagged 4.0 are source-compatible for OTP's current use, but CacheLayer 4.0 intentionally changes signed-record identity binding and other storage behavior. OTP therefore moves directly to CacheLayer `^4.0`; 3.x is not a supported runtime line for OTP 7.0.

1. Create clean isolated consumer/test installations for CacheLayer 4.0 minimum and current supported 4.x stable on PHP 8.4/8.5.
2. Exercise memory, SQLite, live Redis, and the advertised coordinated-lock fallback. Cover initialization, CAS, consuming claims, monotonic state, TTL, corruption, backend failures, and unknown outcomes.
3. Verify the optional Runwire package can be absent with CacheLayer 4.x and normal OTP calls still work.
4. Require `infocyph/cachelayer:^4.0` and validate the lower-bound and current 4.x dependency sets explicitly. OTP 7.0 must not resolve CacheLayer 3.x.
5. Keep authentication state on authoritative direct backends. Do not switch it to tiered, Node/Cluster invalidation caches, process memoization, or fail-open storage to obtain runtime features.
6. Preserve OTP state key domains and encodings, but do not claim CacheLayer 3.x signed records are directly readable by 4.0. Document a coordinated cutover for live authentication state, including durable monotonic replay/counter state, and treat mixed CacheLayer 3.x/4.x workers as unsupported during migration unless a tested bridge is provided.

## Runwire 2.1: useful, but narrowly scoped

Useful capabilities are cooperative bounded lock contention, cancellation/deadline checks, and explicit request/task lifecycle propagation. HMAC arithmetic, secure random generation, and signature verification do not inherently become faster through an event loop. Synchronous Redis/PDO/filesystem/WebAuthn calls remain synchronous.

Tagged CacheLayer 4.0 exposes `RunwireIntegration::bind/share/release` and `RunwireExecutionContext`. Its actual cooperative sleep/checkpoint callers are Cluster consumption and worker maintenance. OTP's lock paths (`FileLockProvider`, `PdoLockProvider`, `PollingLockProviderHelpers`) still use `microtime(true)` and `usleep()`. Therefore **upgrading CacheLayer alone does not make OTP lock waiting cooperative**. OTP should not start those unrelated background services.

### Passed-instance public contract

Proposed API, not implemented:

- One optional `Infocyph\OTP\Integration\RunwireContext` instance carries the exact supplied `RuntimeContext`, optional current `RequestContext`, and optional host-owned `CoroutineScope`.
- Its independent justification is validation of runtime identity, request lifecycle, process/generation binding, and capability/cancellation policy. Reuse the existing Runwire objects; do not recreate their scheduler, context, token, deadline, or metrics abstractions.
- Before adding it, check whether a suitable existing Runwire public aggregate can provide all those guarantees. CacheLayer's aggregate currently only validates request/runtime identity; merely renaming that DTO would not justify another type.
- Pass this instance as a trailing optional named `runwire` parameter on operations that own state/I/O: GenericOtp generate/verify/delete; GridOTP issue/verify; Passkey begin/finish; AOTP issue/verify; and stateful HOTP/TOTP/OCRA/MobileOTP verification. Forward it through convenience methods to the one state owner.
- Keep secret-only arithmetic/provisioning APIs unchanged. Recovery stores already own their mutation implementation; do not change their interface just for symmetry. Add cancellation around a recovery operation only if the active integration contract needs it, never by wrapping it in background work.
- Never store a request/scope in a process-wide singleton or a long-lived factor object. Construct a short-lived integration instance per request/task and forward the same object through intermediate libraries.

Illustrative future use (names above are proposed):

```php
$execution = new \Infocyph\OTP\Integration\RunwireContext(
    runtime: $hostRuntimeContext,
    request: $hostRequestContext,
    scope: $hostCoroutineScope,
);

// Direct call, or forward $execution unchanged through another library.
$accepted = $genericOtp->verify($binding, $submittedCode, runwire: $execution);
```

The host supplies these objects from its active lifecycle. OTP must not manufacture a standalone context and treat it as the active framework runtime. The framework retains bootstrap/fork/rebind/shutdown responsibility. Cross-library interoperability means forwarding these actual references, not rediscovering a global runtime.

### Capability selection and execution

| Available context | Behavior |
| --- | --- |
| No Runwire installation / no supplied instance | Existing synchronous path; no runtime discovery, workers, listeners, timers, or background tasks |
| Runtime supplied without request/scope | Normal path; no invented scope or process-global request state |
| Request supplied without coroutine capability | Honor request cancellation/deadline at safe boundaries; keep synchronous execution |
| Compatible live scope and `RUNWIRE_COROUTINES` | Cooperative bounded waits and scope cancellation checks |
| Mismatched/completed/stale context | Explicit configuration/lifecycle failure, not silent context substitution |
| Selected operation throws or may have committed | Propagate; never repeat via synchronous fallback or report an ordinary mismatch |

Implementation stays in `Support/CacheLock.php` plus the justified optional integration boundary:

1. Check cancellation/deadline before beginning state-changing work. Respect both supplied request and scope cancellation; never cancel or close the host's scope yourself.
2. For lock contention, either consume a proven instance-based cooperative facility from CacheLayer, or repeatedly call the existing provider with zero wait, then use the supplied scope's `sleep()` between attempts. Preserve the original one-second maximum wait, include acquisition time in that budget, and use a monotonic deadline capped by the host's remaining budget.
3. A zero-wait acquisition can still block in a backend call. Keep connection/read timeouts explicit and document that cooperative polling cannot preempt synchronous I/O.
4. Keep eight-attempt CAS bounds. Yield between contention retries only where measured fairness needs it; preserve read/compare/update ordering.
5. Never yield arbitrarily between ownership verification and mutation. Solve F6 independently; cooperative scheduling is not a fencing mechanism.
6. Release acquired locks on every exception path. Do not let cancelled sleeps prevent required synchronous cleanup. Do not report a committed consumption as uncommitted because a later cancellation checkpoint fired.
7. Do not call Runwire execute/run/spawn/close/join or runtime start/stop methods to manage the host. Do not change adaptive HTTP scheduling policy.
8. Do not bind/release CacheLayer's process-static runtime per OTP call. That could interfere with other consumers. If an application already binds CacheLayer, leave its ownership with that application.

Dependency packaging: add `infocyph/runwire:^2.1` to development coverage and `suggest`, not runtime `require`. Keep typed references isolated so production loading and normal calls succeed when the package is absent. If testing later reveals unsupported Runwire versions, encode the supported optional range appropriately and test Composer resolution; do not rely solely on suggestion prose.

Acceptance must exercise framework → OTP and framework → another library → OTP, two interleaved requests, sibling tasks, nested calls, completed/mismatched contexts, generation changes, missing capabilities, absent package, cancellation before lock/while waiting/before mutation, exceptions after commit, and cleanup. Assert exact object identity and zero OTP-owned workers/loops/tasks. Do not infer scope ownership from mere package installation or from `RuntimeContext` capability flags alone.

## Implementation sequence and release gates

### Implementation tracker

| Batch | Scope | Implementation | Focused QA | Status |
| --- | --- | --- | --- | --- |
| 1 | F1 diagnostic redaction | Complete | Complete (Pest; full gate retains Batch 6 F5 skip findings) | Complete |
| 2 | F3 strict protocol validation | Complete | Complete (Pest; full gate retains Batch 6 F5 skip findings) | Complete |
| 3 | F2 Passkey malformed-input boundary and real ceremony fixtures | Complete | Complete (Pest/Pint/analyzers; full gate retains Batch 6 F5 skip findings) | Complete |
| 4 | F4 GridOTP entropy policy and migration | Complete | Complete (GridOTP regressions green; full gate retains Batch 6 F5 skip findings) | Complete |
| 5 | F6 stale-owner/fencing review and state compatibility coverage | Complete | Complete (fenced CAS regressions, v1 state keys, Pest/Pint green; Redis acceptance continues in Batch 6) | Complete |
| 6 | F5 prerequisite, skip, Redis, and dependency-audit cleanup | Complete | Complete (4 QA lanes, live Redis/SQLite, zero skips, analyzers/clean install/benchmarks green) | Complete |
| 7 | CacheLayer 4.0-only migration, compatibility, and dependency floor | In progress | Running (^4.0 floor + full matrix) | In progress |
| 8 | Performance baseline and minimal optional Runwire integration | Pending | Pending | Pending |
| 9 | Runwire lifecycle, concurrency, and consumer coverage | Pending | Pending | Pending |
| 10 | Documentation, migration/rollback, full release acceptance | Pending | Pending | Pending |

Tracker rule: update this table in the same branch as implementation. A batch is complete only after its scoped implementation and focused QA are both complete; final release gates remain separate.

Known upstream release blocker: current stable `phpbench/phpbench` 1.7.0 still requires abandoned `doctrine/annotations:^2.0`. Composer audit reports no security advisory and exits successfully, but the dependency-hygiene warning cannot be removed from OTP without forcing a development PHPBench line or changing PHPForge. Keep this visible through final release acceptance rather than suppressing it.

### Workstream A — hardening and state safety

1. Add failing regressions for F1–F3 and realistic WebAuthn fixtures; fix within existing owners.
2. Document and test F4; design migration-aware enrollment policy. Complete F6 fault-injection triage and correct any reproduced state-safety defect before accepting affected production claims.
3. Resolve F5 prerequisite/skipper/dependency issues. Preserve checks and thresholds.
4. Update security/error/passkey/GridOTP documentation and the consolidated release notes; do not claim hardening fixes that are still planned.
5. Run focused regressions during implementation and inspect generated edits. If F6 requires a breaking persistence change, include an explicit migration and reassess the single candidate's major version.

### Workstream B — dependency and runtime integration

1. Prove CacheLayer 4.0/current-4.x compatibility in clean installations and enforce the `^4.0` floor.
2. Record a representative baseline before adding the optional Runwire path.
3. Implement the smallest passed-instance contract and capability use above, preserving default behavior and state formats.
4. Add consumer examples for both call-chain shapes, normal PHP-FPM/CLI, and a persistent host. Document worker-local resource creation after fork.
5. Complete integration regressions and performance/lifecycle acceptance against the combined hardening and integration changes.

### One combined release candidate

1. Complete both workstreams and consolidate their code, dependency constraints, tests, documentation, examples, migration/rollback instructions, and release notes into one candidate.
2. Confirm 7.0.0 preserves OTP public protocol/result contracts while documenting the intentional CacheLayer 4.0 dependency and signed-state migration break.
3. Run the installed PHPForge workflow on the combined candidate: doctor/config checks, sequential `ic:process`, `ic:tests:details`, then `ic:tests` or `ic:release:guard`; inspect all generated edits. Run Composer audit/validation, compatibility/deprecation checks, and the complete acceptance matrix below.
4. Require passing local verification and CI on the exact final revision, including security regressions, all supported dependency lanes, optional-package absence, Runwire lifecycle behavior, and representative performance evidence. Earlier workstream runs do not replace combined-candidate validation.
5. Publish one immutable release and one tag only after every required gate is satisfied. An unresolved required finding, migration, or verification blocker holds the whole release; it does not trigger an intermediate publication.

### Required acceptance matrix

| Axis | Required evidence |
| --- | --- |
| PHP | Real PHP 8.4 and 8.5; actual extension/platform checks; next intended runtime compatibility/deprecation check when available |
| Dependencies | Lowest and stable sets with CacheLayer 4.0 minimum/current supported 4.x only; supported WebAuthn 5.3 minimum/current; Runwire 2.1/current supported 2.x |
| Optionality | Clean no-dev consumer without Runwire/WebAuthn; clear unavailable-feature behavior; full integration jobs with each installed |
| State backends | Memory as unit evidence, SQLite contention, live Redis contention, advertised lock fallback; no skipped required cases |
| Authentication | RFC vectors; valid/malformed/expired/replayed input; exact-one-winner races; monotonic high/low races; corrupt state; key rotation; unknown commits; stale leases |
| Runwire host | Direct and nested-library forwarding; concurrent request/task isolation; cancellation/deadline; lifecycle cleanup; no takeover of workers/event loops |
| Installation/docs | Clean Composer production install, autoload check, executable examples, documentation build, accurate migration/rollback instructions |
| Release | Stable runtime constraints, no unresolved audit/quality gates, reviewed final diff, CI for the exact immutable candidate before tag |

### Performance and architecture acceptance

- The duplicate detector reported eight clone groups / 517 duplicated lines (7.87%), below its failing threshold. Review every group during touched-code work and centralize genuinely repeated state/validation logic across affected call sites. Preserve protocol-specific semantics; a structural similarity report alone does not justify merging unrelated protocols or introducing generic state-machine layers.
- Preserve existing atomic paths and avoid runtime checks in pure arithmetic loops. Do not cache OTPs, secrets, or verification decisions to improve timings.
- Keep a single optional integration boundary; no OTP container, runtime manager, worker pool, provider registry, generic middleware stack, or new clock abstraction around methods that already receive deterministic timestamps.
- Before a new public type is added, record its ownership/invariants, reuse alternatives, public compatibility, call overhead, and expected benefit. Keep other fixes as private methods in their current owners. Existing cohesive files are not split merely for their line count.
- Measure first call, warm calls, accepted/rejected/malformed/expired/replayed input, contention, backend failure, and cancellation. Include complete success assertions in benchmark workloads.
- Compare normal execution, Runwire installed but unused, missing capability, and cooperative contention under equivalent workloads.
- On a stable host, run at least three warmed sustained trials per selected concurrency level, record median successful RPM plus p50/p95/p99, errors/timeouts, CPU, steady/peak memory, queue growth, and backend connections. Include a persistent-worker soak and cold-start measurements separately.
- Establish workload-specific budgets from the baseline before implementation. Proposed normal-path regression budget: at most 2% median RPM loss, with zero incorrect acceptance or unexpected test-workload errors, no sustained queue growth, and bounded worker memory. Choose absolute tail-latency/memory limits from the representative deployment and record them before comparing results.
- A performance difference within measurement noise is not a gain. If optional runtime work adds complexity without a demonstrated capability/lifecycle or throughput benefit, reduce or defer it. Never remove security checks or loosen budgets to manufacture a passing result.

## Rollback and completion

Deploy an immutable tested release. Keep existing state keys and formats unless a separate migration is explicitly required. Roll back optional Runwire behavior by omitting the integration instance; OTP must not stop the host runtime. Verify previously issued codes, counters, and pending challenges behave safely across mixed versions and rollback.

Completion requires resolved findings or explicitly documented migration blockers, passing required matrices without suppressed findings/skips, verified consumer examples, realistic performance evidence for runtime claims, and final-revision CI. This audit is a plan for that work, not release approval.

## Sources

- Local source and tests at the revisions listed above; line references identify the audited OTP revision.
- [Runwire published package metadata](https://root.packagist.org/packages/infocyph/runwire) confirms 2.1 and its PHP/platform requirements.
- [CacheLayer published package metadata](https://root.packagist.org/packages/infocyph/cachelayer) describes optional Runwire 2.1 integration in 4.0. Actual OTP-relevant wait behavior was checked against tagged local source, not inferred from the overview.
- `../vendor/infocyph/phpforge/resources/engineering-principles.md` and `../vendor/infocyph/phpforge/resources/AGENTS.md` define the implementation, measurement, and quality-gate requirements used here.
