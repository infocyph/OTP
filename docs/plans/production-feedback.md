# OTP — production feedback and upstream action plan

Status: **open — initial investigation and release planning** · 2026-11-26

Baseline: Exact installed specialist version pending inventory. Release target to be selected after root-cause isolation; no version bump authorized by this file.

## Findings

- [ ] **OTP-001 (P1 candidate):** [PDO OTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376679657) CacheLock.php:408 Unable to acquire OTP state lock in GenericOtp::generate; [durable MySQL](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376682485), [OCRA rotation PDO](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376832186). Trace atomic primitive, lock token ownership, TTL, transaction isolation and cache backend; distinguish CacheLayer bug, config or OTP transition issue. Native independent state/lock evidence; concurrent generate/verify exactly one consumer, no replay, safe expiry and rotation.
- [ ] **OTP-002 (P1 candidate):** [Redis Cluster TOTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376823288), [minority TOTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376823683), [mobile shard loss](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376826426), [OCRA counter](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376822095); historical topology startup failures corrected for representative cluster election. Requalify each native protocol/state machine across minority/shard loss/recovery; authoritative fail closed, no stale proof success, independent ledger and no owner overwrite. Latest OTP election control passes; not all variants verified.
- [ ] **OTP-003 (cross-owner):** Foundation recovery ID exceeds 64-char schema (FND-001) is not an OTP generator defect. Retest durable enrollment/recovery after [Foundation](foundation.md) fix; isolate [CacheLayer](cachelayer.md) locks. Preserve direct Generic/TOTP/HOTP/OCRA/AOTP/Grid/MobileOTP controls, passkey factor and registration, drift, exhaustion and key rotation.

## Batches
A: PDO lock/native state and exact ownership; B: distributed topology/replay; C: all protocol families, Foundation enrollment and recovery races. No assertion weakening, expiry bypass or insecure lock fallback.

## Evidence and execution rules

Baseline: [run 45661843498](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498) (PHP 8.5, c5c5efa; 1,505/2,179 jobs passed), [run 45756151480](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45756151480) (6f73868; 45/54 passed, all 14 worker types operational), [defect register](../qa/production-defect-register.md), [capability inventory](../qa/capability-coverage.md). All 22 full-run job-summary pages were screened, representative logs reviewed, and existing source-traced findings carried forward. Counts and scenario names are not root-cause counts. Exact installed versions not explicitly established below must be taken from each job's package inventory. This is an initial upstream handoff, not completed root-cause or release qualification. Do not treat an uninvestigated failure as a library defect, or absence of a confirmed finding as proof of defect-free behavior.

Follow [PHPForge engineering principles](https://github.com/infocyph/PHPForge/blob/main/resources/engineering-principles.md); use GitHub-hosted workers, one logical batch per commit, update tracker with exact source/version/job evidence. No skips, vendor edits, weakened assertions, security overrides, dependency revision pins, or automatic merge. Keep frozen 2,177 routine tuples and two native gRPC modes; add only justified regression cases. Run published-package consumer tests on PHP 8.5 and supported upstream CI versions; final full matrix after upstream releases. Keep fixture/third-party fixes separate. No upstream implementation performed in this feedback batch.

## OTP implementation tracker — 2026-11-27

- [x] A: Runwire ^4.0.1, CacheLayer ^4.1, compatible dependency updates and PHP 8.6 matrix.
- [ ] B: PDO lock ownership and native atomic state.
- [ ] C: Distributed topology and replay.
- [ ] D: Protocol coverage and cross-owner recovery qualification.
- [ ] E: PHPStan (179) and Psalm (940) findings on baseline f40d42e; root-cause fixes, no suppressions.
- [x] F: Prefer-stable Passkey regression (WebAuthn 5.3.15 baseline).
- [ ] G: Documentation and migration updates.
- [ ] H: Hosted QA, security and sustained performance gates.

Baseline workflow: https://github.com/infocyph/OTP/actions/runs/44992998393 (7 passed, 4 failed, 2 skipped). Findings pending reproduction on updated dependencies. Preserve public contracts and fail-closed semantics. Apply PHPForge CORE, FLOW, SEC, DATA, COMPAT, CONFIG, OPS, PERF and remaining applicable rules with evidence per batch. No automatic merge.

### Batch A — dependency manifest and runtime matrix

- Implemented target constraints: CacheLayer ^4.1, Runwire ^4.0.1, constant-time-encoding ^3.1.5, WebAuthn ^5.3.17. Bacon QR ^3.1.1 is current; PHPForge tracks main. Confirmed published upstream release tags; package resolution and compatibility pending hosted QA.
- Added PHP 8.6 to the QA matrix. Historical Runwire 3 performance baseline remains unchanged intentionally; current candidate uses Runwire 4.
- Updated README and installation guidance. COMPAT/CONFIG/FLOW/PERF verification pending; no change to authentication semantics or performance thresholds.

### Batch F — WebAuthn assertion fixture

- Replaced the legacy assertion fixture (attested-credential-data flag set during authentication, omitted crossOrigin) with an ES256 signature over the actual issued challenge, correct RP hash, UP/UV flags and counter. Added invalid-signature rejection before valid authentication and replay rejection after consumption. No production validation weakened. FLOW-02/SEC: hosted test pending; do not close until confirmed.

### Batch B — PDO native state coordination

- Historical PostgreSQL job 139376679657: installed CacheLayer 4.0.3, GenericOtp generation failed in the whole-record advisory-lock path. Compared CacheLayer 4.0.3 and 4.1 PdoLockProvider blobs (identical); precise advisory failure cause is not established.
- CacheLayer 4.1 exposes native conditional PDO mutations, with row locks/transactions and corrected PostgreSQL binary payload binding. Select that supported capability before any lock attempt, not as a runtime fallback. No state format/key change, and no mixed old/new writers; deployment guidance added.
- Added mandatory real MySQL, MariaDB and PostgreSQL independent-connection replay tests in the hosted matrix. SEC/DATA/FLOW/PERF evidence pending; upstream advisory lock issue remains separately unconfirmed, as do durable recovery/rotation scenarios.

### Batch F/B — hosted regression follow-up

- Run 45955159443 (PHP 8.4 prefer-lowest and PHP 8.6 prefer-stable): 201 tests passed including all three PDO services; one new Passkey negative-signature test failed because upstream COSE DER parsing threw InvalidArgumentException. PHPCS reported an unused test callback parameter.
- Map the verifier's malformed-input exception to a non-consuming malformed result; keep stored options decoding outside the catch. Added separate DER-malformed and well-formed wrong-signature assertions, followed by successful authentication/replay; removed the unused callback parameter. New head verification pending. PDO lock-provider root cause remains separate from native-state path verification.

### Batch E1 — explicit type contracts

- Fixed real mock/stub subtype loss by preserving the input generic type; corrected the SQLite fixture's split generic annotations and interface overrides. Replaced truthiness of environment values with explicit checks (preserving a valid password of '0').
- Clarified recovery-state trust-boundary shape, numeric operands, provisioning parsing and OCRA mandatory match; unified label return documentation. Added explicit interface overrides. TYPE/COMPAT/FLOW evidence pending hosted analysis; no exclusions or suppressions.

### Batch E2 — source exception contracts

- Mapped direct missing-throws diagnostics in the PHP 8.5 analysis of da8fa1e (run 45955159443) to their enclosing source methods and added precise PHPDoc declarations across 32 source files. This is a documentation-only pass: no exception catching, analyzer suppression, control-flow change or assertion weakening. Propagated caller contracts and other diagnostic categories still require hosted analysis and follow-up.

### Batch E3 — hosted QA follow-up

- Run [45955469231](https://github.com/infocyph/OTP/actions/runs/45955469231): PHPStan 137 findings (previously 179); Psalm 987 (previously 1000). Pest passed on PHP 8.5 prefer-stable; Pint flagged one missing blank line in Passkey, corrected here. Earlier native PDO regression tests passed on all three database engines. Final certification remains open.
- OTP-002 historical cluster jobs 139376823288, 139376823683, 139376826426 and 139376822095 terminated with Docker container-not-running errors (CacheLayer 4.0.3); these do not establish an OTP defect. Real cluster requalification remains outstanding.

### Batch E4 — test namespace contracts

- Run [45955741826](https://github.com/infocyph/OTP/actions/runs/45955741826), PHP 8.5: PHPStan 138, Psalm 946, including 277 internal class/method findings caused by root-namespace tests accessing library-owned internals. Moved the 16 affected test files into `Infocyph\\OTP\\Tests` with explicit global class imports. No analyzer exemptions or production API changes. Hosted verification pending.

### Batch E5 — Passkey and OCRA trust-boundary contracts

- Last complete run 45955976955: all six functional QA jobs passed, clean install and standard benchmarks passed; PHPStan 138, Psalm 669 (277 internal-access findings eliminated). Sustained gate failed roundtrip 2.12% and concurrent verification 15.46%; no threshold changes.
- Separate valid ceremony state from failure decisions, narrow JSON/EC/signature test fixture values, and declare test-only extensions. Correct OCRA mandatory capture handling without changing valid suites. Hosted validation pending.

### Batch E6 — benchmark measurement types

- Declare the actual workload and repetition shapes, validate CPU usage and cold-start child result payloads, and reject empty measurements. Preserved workload, duration, repetitions and acceptance thresholds. Hosted verification pending.

### Batch E7 — explicit PHPUnit test contexts

- Migrated 13 mock-bearing test files to ordinary PHPUnit test classes, retaining every test body, descriptive TestDox name and dataset. This removes reliance on Pest's dynamically rebound closure `$this` (181 UndefinedMagicMethod diagnostics), without suppressing the analyzer or changing expectations. Pest continues to run PHPUnit tests. Hosted test count and behavior must be verified before closure.

### Batch E8 — state decision and test contract follow-up

- Replaced ambiguous Passkey union return with explicit nullable state/transition slots; retained malformed, expired, replay and mismatch semantics. Retained runtime serializer type validation through the mixed boundary. Added missing exception imports in the namespaced PHPUnit tests, interface override attributes, and concrete test fixture validation for benchmark output, grid and concurrent OTP issuance. Hosted verification pending.

### Batch E9 — propagated source exception contracts

- Mapped the latest completed analysis (run 45963698829) to the actual source methods and added documented propagated exceptions across 21 source files. No change to behavior or suppression. The PHPUnit conversion eliminated magic-method diagnostics but introduced missing-throws findings in the explicit test methods; those remain to be addressed with accurate contracts. Hosted verification pending.

### Batch E10 — remaining type checks and context-free path

- Correct benchmark callback and CPU measurement contracts, strengthen fixtures, and retain malformed credential classification without declaring unproven exception types.
- Bypass Runwire lock acquisition wrapper and empty atomic checkpoints when no context is supplied. Native CAS, lock ownership, cancellation with explicit context and release budgets remain unchanged.
- Hosted verification pending; concurrent SQLite baseline comparison remains open.

### Batch E11 — fixture exception contracts

- Record propagated exceptions reported by Psalm on unchanged explicit PHPUnit methods and test support methods. No ignore rules added. Hosted verification pending.

### Batch E12 — runtime contracts and source complexity

- Run 45964581553: PHPStan 22, Psalm 663; clean install and standard benchmarks pass; all QA jobs blocked by Passkey method ordering. Reordered the static helper and removed redundant list checks (required string keys already exclude lists). Consolidated conditional atomic cancellation checks through the existing null-aware checkpoint, preserving precommit cancellation and retry bounds. Declared the real cancellation contract on GenericOtp generation. Hosted verification pending; sustained performance must be remeasured.

### Batch E13 — remaining test contracts

- Use a mutable typed fixture for the nested GenericOtp CAS test (retains the same interleaving and assertions); explicitly validate stored state before inspecting offsets. Narrow PHPUnit dataset shapes and declare missing lock overrides. Split concurrency fixture into worker creation, barrier and collection phases, preserving process and timing behavior. Hosted verification pending.

### Batch E14 — benchmark process and measurement contracts

- Split repeat aggregation, worker launch/barrier/sample/join and independent result decoding into bounded helpers; validate CLI and process identifiers and reject malformed measurement records instead of silently converting them. Retained four workers, original timings, workloads, resource sampling and acceptance limits. Added lock overrides. Hosted performance and QA verification pending.

### Batch E15 — hostile recovery-store input fixtures

- Keep every deliberately malformed recovery-store dataset, but use mock return callbacks instead of inaccurate implementation return contracts. Preserve the binding, hash, issuance and error assertions. Validate the Redis test process identifier. Hosted verification pending.

### Batch E16 — benchmark fixture lifecycle and QA follow-up

- Run 45966570611: PHPStan reduced to 3 findings; all three benchmark jobs and clean install succeeded, Pest passed; remaining QA failure is release-gate formatting. Initialize wait status, keep the explicit array assertion and remove its duplicate, normalize whitespace and strictly validate benchmark arguments/PID. Declare pcntl/posix development dependencies. Initialize benchmark fixtures at construction while retaining PHPBench reset hooks, and exercise the four actual fixtures from a discovery/reset test. No workload or regression threshold reduced. Psalm exception contracts and dynamic baseline autoload remain outstanding.

### Batch E17 — propagated exception contracts

- Mapped the exact diagnostics from PHP 8.5 job 140396634550 to named source, benchmark and test methods. Documented propagated exception contracts across affected files, including constructor initialization of benchmark fixtures. No runtime changes or suppression rules in this batch. Re-run both analyzers because downstream propagation can expose additional caller contracts.
- Performance run 45964581553: generate -0.44%, roundtrip +0.25%, concurrent SQLite +36.14% regression; HTTP c=8 +6.59%, c=32 +6.81%. Cache::sqlite delegates to Cache::pdo with PdoLockProvider; selecting PDO CAS for all drivers changes SQLite from per-key coordinated writes to transaction-based CAS. CacheLayer 4.1 exposes no public driver/lock-mode accessor. Need safe driver-aware selection or upstream atomic throughput improvement; do not revert network PDO safety or weaken the 2% gate. Final performance, Redis Cluster, and Foundation consumer qualification remain open.

### Batch E18 — explicit benchmark entry points

- Run 45966876266: all six functional QA jobs, clean install, and three standard benchmark jobs passed. PHPStan had two process-status findings, corrected with runtime type validation. Psalm identified 28 private properties reachable only through PHPBench reflection; the smoke test now explicitly exercises every measured subject after its normal reset hook. Dynamic external autoload includes replaced with verified PHP CLI auto_prepend_file for paired runs; the local autoloader remains a fixed-path include. This prevents accidental candidate/baseline autoload substitution. No workload, thresholds, or authentication checks removed. Hosted certification pending.

### Batch E19/G — final diagnostic propagation and migration guidance

- Run 45967250591: PHPStan 1, Psalm 131 (PHP 8.5); five functional QA jobs and three standard benchmarks passed, sixth QA and sustained gate still running at inspection. Document actual remaining propagated exceptions from job 140399026663, remove unused hostile-fixture exception declaration, and isolate wait-status validation in a mixed boundary helper so both analyzers agree. No suppressions. Verify the new head before closure.
- Synchronize current migration guidance with Runwire 4.0.1, CacheLayer 4.1, WebAuthn 5.3.17, and PDO state writer drain requirement. Keep historical release guidance intact.
- Dependency matrix and Passkey regression verified by complete run 45966876266; mark A and F implemented and verified. Other gates remain open.

### Batch E20 — remaining propagated exception contracts

- Run 45967753545, PHP 8.5 analysis: PHPStan passed; Psalm 73 errors, all missing propagated exception contracts. Added exact declarations on source, test and benchmark methods from job 140400504521, without suppressions or behavior change. Five QA jobs passed; PHP 8.5 prefer-lowest failed only the benchmark smoke test's existing absolute p99 gate (202 tests passed). Standard benchmarks and clean install passed. Final head verification remains open.

### Batch E21 — remaining caller contracts

- Run 45968200172, PHP 8.5 job 140401963178: PHPStan passed; Psalm reduced to 47 errors, all propagated exceptions. Added exact method contracts; no suppressions or behavior changes. PHP 8.5 prefer-lowest QA passed on this head (previous p99 smoke failure did not recur). Benchmark PHP 8.6 encountered upstream GitHub codeload HTTP 429 during dependency download, not a code failure. All 51 inline review threads resolved by the code-scanning bot at inspection. Final matrix pending.

### Batch E22/H — benchmark failure evidence and caller contracts

- Run 45968479044: PHPStan passed, Psalm 12 errors (six distinct exception diagnostics). Added the exact remaining benchmark caller contracts. All three benchmark jobs passed, but both PHP 8.5 QA jobs failed the 1 ms p99 budget in the parallel benchmark reporting smoke test; the other four QA jobs passed.
- Preserve every absolute budget and the nonzero benchmark exit on breach. Write measurement JSON before enforcing those budgets so failure evidence survives; the reporting test verifies the exit status against measured p99, peak memory and growth, including an explicit breach diagnostic. Dedicated benchmark and sustained release jobs still fail on an over-budget measurement. Added workflow-level PR concurrency cancellation to prevent superseded sustained jobs from accumulating. No benchmark workload, sample count or threshold changed.
- CacheLayer 4.1 wraps SQLite file locks in PdoLockProvider, with no public way to distinguish the effective lock. Native PDO CAS selection remains safe but affects the concurrent SQLite workload. An upstream capability fix is needed; attempted to create CacheLayer branch patch/pdo-lock-capability and received GitHub 403. No upstream files changed. Final performance gate remains open.

### Batch E23 — taint and legacy protocol boundaries

- Run 45968853283 PHP 8.4 analysis reported six security findings after ordinary Psalm exception diagnostics cleared: three CLI-controlled output paths, one cold-start process argument, and two MD5 calls in the legacy mOTP implementation. Changed the benchmark report interface to stdout or a fixed Composer build path; the HTTP harness now uses its private process working directory rather than a CLI-supplied write destination. Cold-start subprocesses use the known local autoloader. Updated all current internal callers, retaining paired baseline/candidate measurements and budgets. No taint suppressions.
- Consolidated the duplicate protocol-required MD5 operation without changing the legacy mOTP wire calculation. SEC-06 requires preserving established protocol algorithms; FLOW-02 requires explicit approval for any scoped exception. A remaining WeakHash finding cannot be honestly fixed by substituting SHA-256 (that breaks mOTP). Do not suppress or remove this compatibility API without explicit approval. Hosted verification pending.
- Historical durable MySQL job 139376682485 actually fails in Foundation/Epicrypt MFA key resolution (invalid 32-byte key), not OTP. OCRA rotation job 139376832186 fails with CacheBackendException in a concurrent race; precise SQL failure remains unproven. The consumer workload must be retested on published compatible versions.
