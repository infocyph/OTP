# OTP — production feedback and upstream action plan

Status: **direct functional implementation verified — release certification blocked** · 2026-11-27

Baseline: Exact installed specialist version pending inventory. Release target to be selected after root-cause isolation; no version bump authorized by this file.

## Findings

- [ ] **OTP-001 (P1 candidate):** [PDO OTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376679657) CacheLock.php:408 Unable to acquire OTP state lock in GenericOtp::generate; [durable MySQL](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376682485), [OCRA rotation PDO](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376832186). Trace atomic primitive, lock token ownership, TTL, transaction isolation and cache backend; distinguish CacheLayer bug, config or OTP transition issue. Native independent state/lock evidence; concurrent generate/verify exactly one consumer, no replay, safe expiry and rotation.
- [x] **OTP-002 (P1 candidate, direct upstream qualification):** [Redis Cluster TOTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376823288), [minority TOTP](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376823683), [mobile shard loss](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376826426), [OCRA counter](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498/job/139376822095); historical topology startup failures corrected for representative cluster election. Requalify each native protocol/state machine across minority/shard loss/recovery; authoritative fail closed, no stale proof success, independent ledger and no owner overwrite. Direct upstream qualification passed 36/36 cases again on 2f02b3f (see Batch H4). Published consumer requalification remains part of H; no guarantee of arbitrary asynchronous replication data-loss recovery.
- [ ] **OTP-003 (cross-owner):** Foundation recovery ID exceeds 64-char schema (FND-001) is not an OTP generator defect. Retest durable enrollment/recovery after [Foundation](https://github.com/infocyph/infbyte-app-experiment/blob/main/feedbacks/foundation.md) fix; isolate [CacheLayer](https://github.com/infocyph/infbyte-app-experiment/blob/main/feedbacks/cachelayer.md) locks. Preserve direct Generic/TOTP/HOTP/OCRA/AOTP/Grid/MobileOTP controls, passkey factor and registration, drift, exhaustion and key rotation.

## Batches
A: PDO lock/native state and exact ownership; B: distributed topology/replay; C: all protocol families, Foundation enrollment and recovery races. No assertion weakening, expiry bypass or insecure lock fallback.

## Evidence and execution rules

Baseline: [run 45661843498](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45661843498) (PHP 8.5, c5c5efa; 1,505/2,179 jobs passed), [run 45756151480](https://github.com/infocyph/infbyte-app-experiment/actions/runs/45756151480) (6f73868; 45/54 passed, all 14 worker types operational), [defect register](https://github.com/infocyph/infbyte-app-experiment/blob/main/qa/production-defect-register.md), [capability inventory](https://github.com/infocyph/infbyte-app-experiment/blob/main/qa/capability-coverage.md). All 22 full-run job-summary pages were screened, representative logs reviewed, and existing source-traced findings carried forward. Counts and scenario names are not root-cause counts. Exact installed versions not explicitly established below must be taken from each job's package inventory. This is an initial upstream handoff, not completed root-cause or release qualification. Do not treat an uninvestigated failure as a library defect, or absence of a confirmed finding as proof of defect-free behavior.

Follow [PHPForge engineering principles](https://github.com/infocyph/PHPForge/blob/main/resources/engineering-principles.md); use GitHub-hosted workers, one logical batch per commit, update tracker with exact source/version/job evidence. No skips, vendor edits, weakened assertions, security overrides, dependency revision pins, or automatic merge. Keep frozen 2,177 routine tuples and two native gRPC modes; add only justified regression cases. Run published-package consumer tests on PHP 8.5 and supported upstream CI versions; final full matrix after upstream releases. Keep fixture/third-party fixes separate. No upstream implementation performed in this feedback batch.

## OTP implementation tracker — 2026-11-27

- [x] A: Runwire ^4.0.1, CacheLayer ^4.1, compatible dependency updates and PHP 8.6 matrix.
- [ ] B: PDO lock ownership and native atomic state.
  - [x] B-direct: Network PDO native state selection, bounded confirmed rollback handling, independent ownership, expiry and contention regressions verified.
  - [ ] B-upstream: CacheLayer effective lock capability, SQLite throughput and historical advisory-lock root cause.
- [x] C: Distributed topology and replay (36/36 Redis/Valkey jobs on 2f02b3f; published consumer requalification remains H).
- [ ] D: Protocol coverage and cross-owner recovery qualification.
  - [x] D-direct: All OTP families, native Passkey registration/assertion, durable 77-byte recovery identity and cross-owner consumption/rotation verified.
  - [ ] D-upstream: Foundation FND-001 schema migration and published-package enrollment/recovery qualification.
- [ ] E: PHPStan (179) and Psalm (940) findings on baseline f40d42e; root-cause fixes, no suppressions.
  - [x] E-direct: PHPStan zero errors across all versions; all non-MD5 Psalm findings fixed; all other review threads resolved.
  - [ ] E-legacy: Resolve protocol-required MobileOTP MD5 versus WeakHash via explicit compatibility/security decision (CORE-01/FLOW-02/SEC-06).
- [x] F: Prefer-stable Passkey regression (WebAuthn 5.3.15 baseline).
- [x] G: Documentation and migration updates (warning-free hosted Sphinx build on 5e0ce3d).
- [ ] H: Hosted QA, security and sustained performance gates.
  - [x] H-functional: Six supported QA variants, 36 topology cases, three standard benchmarks, clean install and documentation build green on 2f02b3f.
  - [ ] H-performance: Stable paired SQLite measurement, 2% throughput budget at every workload/concurrency, and HTTP/soak certification.
  - [ ] H-release: Legacy security decision and published-package consumer matrix after upstream fixes; final tracker reconciliation.

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

### Batch B2 — native OCRA absent-row contention

- Added real MySQL/MariaDB/PostgreSQL regression for initially absent non-counter OCRA replay state: four independent connections race to consume one proof, exactly one succeeds, a separate connection reads the native marker, repeat rejects, and replacement factor generation is isolated. This reproduces the missing-row atomic claim boundary implicated by historical OCRA PDO rotation job 139376832186 without assuming a database deadlock or hiding any backend exception. Retained GenericOtp native regression. Hosted matrix pending.

### Batch E24/B3 — remaining QA and native SQL failure evidence

- Latest completed run [45969337132](https://github.com/infocyph/OTP/actions/runs/45969337132): PHPStan passed; Psalm two findings (PDO fixture constructor exception and legacy mOTP WeakHash). Corrected the fixture exception declaration and MobileOTP method ordering; retained exact mOTP digest per SEC protocol compatibility rule. No suppression introduced.
- PDO OCRA absent-row contention reproduced in MariaDB in PHP 8.5 prefer-stable and PHP 8.4 prefer-lowest. Other QA failures are formatting. Capture nested exception class/code/message from forked workers, without converting backend failures into successful or replay outcomes, so the actual SQL error can be isolated. CacheLayer 4.1 transaction code uses SELECT FOR UPDATE then INSERT IGNORE on MySQL-family drivers; missing-row gap-lock deadlock is a hypothesis, not yet verified. CacheLayer branch creation again denied (403).
- Sustained RPM: generate +1.42%, roundtrip +1.72%, concurrent +0.10% (all within 2% budget); HTTP throughput improved at all concurrency levels, but concurrency 1 failed the 2.5% variance criterion. No threshold changes. Final certification open.

### Batch B4 — confirmed database transaction rollback handling

- Run [46018693825](https://github.com/infocyph/OTP/actions/runs/46018693825), jobs 140572528240/257/311/366/475: native absent-row OCRA regression reported CacheBackendException -> PDOException SQLSTATE 40001, native error 1213 (InnoDB deadlock and full transaction rollback). The failure is now source-traced, not inferred from a generic backend exception. CacheLayer write access remains denied.
- OTP-side containment: retry only native set-if-absent operations on an authenticated PDO backend where the immediate PDO exception identifies SQLSTATE 40001 and error 1213. Re-read authoritative state in the existing eight-attempt loop; do not retry unknown commit outcomes, arbitrary SQL failures, or CAS via a lock. Added explicit winner, exhaustion, and unknown-outcome tests. All existing native database assertions remain intact. Longer-term CacheLayer should avoid absent-row gap-lock deadlocks and preserve original failures on rollback. DATA/SEC/FLOW verification pending hosted CI.
- Psalm on prior head is down to the single protocol-required WeakHash diagnostic; PHPStan passed. No suppression introduced. All standard benchmark jobs passed. Final qualification remains open.

### Batch E25 — remaining nonblocking review diagnostics

- Run [46019160850](https://github.com/infocyph/OTP/actions/runs/46019160850) on 105a08b: all six QA jobs passed (PHP 8.4/8.5/8.6 × lowest/stable), clean install and all three benchmark jobs passed. The native PDO OCRA race and explicit rollback/unknown-outcome regressions are green. PHPStan passed across all versions; Psalm has only the protocol-required WeakHash finding. Sustained gate still running at inspection.
- Narrowed benchmark decoded fields before returning their typed records, constrained mock state assignments to actual array values and removed mixed intermediate results without changing expected behavior. These changes target the 13 open nonblocking mixed-value code-scanning review findings. No analyzer exemptions or thresholds changed. Final hosted recheck pending.

### Batch H2 — stabilize paired HTTP measurement

- Prior HTTP result run 45969337132: candidate single-connection trials 137443/145284/149931 RPM; baseline 121004/123330/122392 RPM. Candidate improved throughput but its single-connection variation violated the 2.5% CV gate. The startup warmup used eight connections and each subsequent measured connection received only one warmup request.
- Prime the actual trial connections concurrently for the already configured warmup interval before starting the measured clock, symmetrically for baseline and candidate at concurrency 1/8/32. Validate each warmup response, handle connection close/reconnect, clean up on failure; keep the same measured duration, repetitions, request workload, soak and 2% regression/2.5% CV limits. Correct the report label to distinguish Runwire 3.x baseline and 4.x candidate. PERF evidence pending; do not claim stable certification before a full hosted pass.

### Batch B5/G — independent native state and deployment guidance

- Run [46019674136](https://github.com/infocyph/OTP/actions/runs/46019674136) on 52d3fa4: six QA jobs, three standard benchmarks, clean install and matrix preparation passed; all three PHPStan analyses passed; Psalm retains only legacy MobileOTP WeakHash at src/MobileOTP.php:241. 68 of 69 inline review threads resolved. Sustained certification in progress at inspection.
- Added independent-connection native PDO tests for concurrent failed-attempt accounting, unchanged absolute expiry, exhaustion, expired live backend record and explicit deletion on MySQL/MariaDB/PostgreSQL. DATA/SEC/FLOW verification pending on new head; no production behavior changed.
- Updated CacheLayer 4.1 storage references and documented that asynchronous Redis replication cannot guarantee replay-marker preservation; operational reconciliation/rotation is required when preservation cannot be established. COMPAT/OPS documentation updated, final cross-library qualification open.
- CORE-01/FLOW-02/SEC-06: no explicit approval for a scoped WeakHash exception or incompatible mOTP removal has been supplied. Preserve the legacy calculation and keep the security gate open. C and D remain unclosed pending real cluster and published Foundation consumer evidence. No thresholds weakened.

### Batch C1 — distributed topology qualification

- Run [46020741402](https://github.com/infocyph/OTP/actions/runs/46020741402) on 3a31425: all six functional QA jobs, three benchmarks and clean install passed, including B5 native PDO expiry/exhaustion/deletion. PHPStan passed; Psalm WeakHash remains. Removed the new mixed-assignment review diagnostic without changing the assertion.
- Added independent GitHub-hosted Redis/Valkey six-node cluster matrix (promotion, minority, shard loss × GenericOtp, TOTP, HOTP, MobileOTP, counter OCRA, challenge OCRA). The isolated fixture verifies a real native record and replication offset, independently confirms unavailable topology and rejected native writes, checks unchanged persisted replay state after recovery, and races four independent clients with owner isolation. A returned success or mismatch during unavailable state is not accepted as an infrastructure failure.
- DATA/SEC/OPS/FLOW: fixture uses only synthetic data, fixed loopback seeds, mandatory assertions and bounded startup/fault deadlines. No production code, public contract, security exception, baseline or performance budget changed. Redis asynchronous failover is only tested after a confirmed replication barrier, not guaranteed under arbitrary data loss. C remains open until hosted evidence is collected. AOTP/Grid/Passkey and published Foundation integration remain D scope.

### Batch D1 — native protocol and ceremony coverage

- Cluster qualification run [46021410013](https://github.com/infocyph/OTP/actions/runs/46021410013) on 3a747ed at inspection: {"success":36} across 36 jobs. Do not close C before a complete green matrix on the final head.
- Reused the existing isolated network PDO fixture through CacheLayerState::pdoFactory. Added nine mandatory hosted AOTP, GridOTP and Passkey registration cases (each of MySQL, MariaDB, PostgreSQL), with independent backend reads, cross-owner rejection, four-client valid-proof races, one winner, persisted terminal state and replay rejection. Grid/Passkey assert the original absolute expiry survives successful consumption. Passkey uses the existing accepted WebAuthn registration fixture and verifies the binding before consumption. No production behavior or existing assertion changed. DATA/SEC/TYPE/FLOW hosted verification pending.
- Rechecked latest published Foundation [4.0.1](https://github.com/infocyph/Foundation/releases/tag/4.0.1): OtpRecoveryCodeStore::factorId returns the 13-byte prefix otp-recovery- plus a 64-byte digest (77 bytes); AuthSchema::createFactorsAndPasskeys still defines the MFA factor ID as 64 characters. Published consumer recovery qualification is blocked by FND-001. Foundation must release the schema/ownership fix; do not shorten IDs, weaken consumer assertions or pin an unreleased dependency to mark D complete. OTP's own recovery replacement/consumption race remains covered by the existing SQLite contract test.

### Batch G1 — current documentation and topology evidence

- [46021410013](https://github.com/infocyph/OTP/actions/runs/46021410013) on 3a747ed and [46021674953](https://github.com/infocyph/OTP/actions/runs/46021674953) on 2351362 each passed all 36 Redis/Valkey topology scenarios. C and the direct upstream OTP-002 qualification are closed with that evidence. Final-head and published consumer qualification remain separate; all tested promotion scenarios required a confirmed replication barrier.
- Current README, installation, replay, security, legacy MobileOTP, API and storage guidance now use the CacheLayer 4.1 floor and distinguish confirmed PDO insert rollback retry from unknown commit outcomes. Historical 7.0/CacheLayer 4.0 migration documentation remains unchanged. Export-ignore the new qa fixtures to keep them out of Composer distribution archives. COMPAT/CONFIG/OPS reviewed; hosted docs build not verified. G content audit completed; final QA/documentation check pending.
- D1 native protocol checks and sustained gate were still running on 2351362 at inspection. Only open inline review finding was the legacy MobileOTP WeakHash; the previous PDO mixed-assignment thread is resolved. E/H remain open. Foundation 4.0.1 consumer defect and CacheLayer upstream advisory-lock investigation remain explicit external blockers, not silently closed.

### Batch E26/D2 — hosted fixture corrections

- [46021675575](https://github.com/infocyph/OTP/actions/runs/46021675575) on 2351362: PHPStan passed; all three standard benchmarks passed; native AOTP/Grid/Passkey tests passed across the six supported QA variants. Five Pest suites passed; PHP 8.6 prefer-lowest had 220 passed and one failure in the pre-existing one-second GenericOtp lock-acquisition test (job 140582932558). Pint and PHPCS reported multiline argument spacing, union spacing and forbidden echo in qa/redis-cluster.php across all six variants.
- Corrected the probe to comply with the configured formatting and checked stdout writes. Replaced the flaky delayed-issuance test's indirect immediate-verification assertion with an exact stored-deadline assertion at the mocked cache write boundary: acquired time must advance, the one-second TTL is preserved, and the stored expiry is at least one second after acquisition and no more than one second after current time. This tests the intended issuance clock directly without weakening the expiration policy. Existing successful verification/replay/expiry tests remain unchanged. FLOW-02/TYPE/SEC: no production change, no skip or gate changes; new head verification pending.

### Batch E27 — qualification namespace boundary

- [46022042778](https://github.com/infocyph/OTP/actions/runs/46022042778) on b21dd0c passed all 36 cluster scenarios again. GitHub security review threads 5294–5297 report use of package-internal Concurrency from the global namespace in the new probe (two calls, class and method diagnostic each). Namespace the qualification script under Infocyph\\OTP\\QA and explicitly import global exception types. No detector exclusions, assertions or behavior changed. Final hosted verification pending.

### Batch D3 — native monotonic protocol completion

- Added 12 mandatory network-PDO scenarios (TOTP/HOTP/MobileOTP/counter OCRA × MySQL/MariaDB/PostgreSQL). Initially absent scalar state is claimed by four independent clients with exactly one winner; a separate factor generation races adjacent values, requires the higher value to win, reads the native monotonic record, rejects both older/equal credentials and verifies the first generation's record is unchanged. This qualifies the same native insert rollback and CAS ownership path used by all monotonic protocols, without altering production code or existing tests. DATA/SEC/FLOW verification pending.
- Direct protocol coverage now includes all OTP families and Passkey, with recovery-store replacement/consumption already covered by its existing durable SQLite race. Foundation published consumer qualification remains externally blocked. No new skip directives, policy changes or performance exceptions.

### Batch E28 — monotonic fixture branch cleanup

- [46022457808](https://github.com/infocyph/OTP/actions/runs/46022457808) on 9bb263a: all 36 Redis/Valkey topology jobs passed (full paginated job list). [46022458177](https://github.com/infocyph/OTP/actions/runs/46022458177): all six QA variants, three standard benchmarks, clean install and preparation passed. D3 native monotonic regression passed across all supported matrix variants. PHPStan found one redundant exhaustive match arm; Psalm reported the same unreachable default plus legacy WeakHash. Sustained gate was still running at inspection.
- Keep the initial protocol match's explicit rejection of unknown names; use its already validated remaining OCRA branch as the final default in the second match. This resolves PHPStan match.alwaysTrue and Psalm TypeDoesNotContainType without changing any dataset, proof, expected result or production behavior. FLOW-02/TYPE verification pending on new head.
- Direct native protocol implementation and regression evidence is complete on 9bb263a, but D remains open for published Foundation recovery/enrollment and B for upstream historical advisory lock root cause. E remains open for the legacy protocol security decision. No exemptions added.

### Batch G2 — enforce the documentation build

- Added a GitHub-hosted Sphinx HTML build using the existing Read the Docs Python 3.13 and docs/requirements.txt configuration, with warnings treated as failures. No duplicate documentation source or dependency manifest. COMPAT/CONFIG/FLOW evidence pending; close G only after the hosted build succeeds.
- Latest published CacheLayer is 4.1 and Foundation is still 4.0.1; no published Foundation recovery schema fix to qualify yet. Prior sustained run 46022458177 had passed benchmark result validation but failed the 2% RPM comparison step; complete HTTP/soak evidence was unavailable at inspection (job log download returned 404). H remains open; do not infer a particular workload regression without the comparison output or weaken thresholds.

### Batch D4/H3 — native assertion ownership and precise performance blocker

- [46023583134](https://github.com/infocyph/OTP/actions/runs/46023583134) on 5e0ce3d: all 36 cluster cases passed again. [Documentation job 140589232973](https://github.com/infocyph/OTP/actions/runs/46023585127/job/140589232973) passed the strict Sphinx build; G closed. Other jobs remained active at inspection.
- Expanded the existing real ES256 assertion fixture to MySQL, MariaDB and PostgreSQL while retaining the original memory case and malformed/wrong-signature tests. Native cases use separate connections, reject another binding without changing state, race four valid signed submissions, require exactly one winner with credential counter 101 and explicit replay for every loser, and preserve the original expiry in the terminal state. Application-owned credential persistence remains outside the OTP contract. DATA/SEC/TYPE/FLOW hosted recheck pending.
- Recovered [46022458177 sustained job 140585429569](https://github.com/infocyph/OTP/actions/runs/46022458177/job/140585429569) logs: generate 1,475,345.51 to 1,474,251.75 RPM (0.07% regression); roundtrip 960,271.15 to 945,281.36 (1.56%); SQLite concurrent verify 413,103.47 to 332,495.98 (19.51%, FAIL). HTTP/soak cancelled before completion. Latest CacheLayer main and 4.1 still wrap SQLite file locks in PdoLockProvider with no public effective-lock accessor; choosing native PDO CAS for all PDO drivers changes SQLite concurrency. Retried CacheLayer branch creation and received HTTP 403 Resource not accessible by integration. Correct fix belongs in the upstream capability boundary (expose actual effective lock provider or native driver capability; qualify both SQLite and network PDO), then remeasure default configuration with a published package. No reflection, runtime lock fallback, benchmark-only configuration change, threshold or workload change. H remains open.

### Batch D5 — durable full-length recovery identity and final-head evidence

- [46023940169](https://github.com/infocyph/OTP/actions/runs/46023940169) on 7c6e1eb: all 36 Redis/Valkey topology jobs passed (complete paginated list). [46023940813](https://github.com/infocyph/OTP/actions/runs/46023940813): six QA variants, three standard benchmarks, clean install, matrix preparation and strict Sphinx build passed; native Passkey assertion race is green. PHPStan passed and Psalm PHP 8.5 log confirms one legacy WeakHash error; the same unresolved review thread remains. Sustained certification was active at inspection; not treated as passed.
- Added a standalone durable SQLite recovery regression using the exact 77-byte Foundation-shaped factor identifiers: cross-owner proof rejection, four independent consumers with exactly one winner, native remaining count, rotation and independent other-owner consumption. DATA/SEC-07/TYPE/FLOW: no production contract change or schema workaround. This proves OTP-side identity capacity only, not Foundation's own migration. Hosted verification pending.
- Rechecked published CacheLayer 4.1 and Foundation 4.0.1; neither upstream fix is available as a published dependency. CacheLayer branch creation retried and again returned HTTP 403 Resource not accessible by integration despite repository metadata reporting push access. B/D/H remain open for external evidence. No legacy mOTP suppression or incompatible removal authorized. No gate changes.

### Batch H4 — verified direct closure and exact release handoff

- [46024793348](https://github.com/infocyph/OTP/actions/runs/46024793348) on 2f02b3f: all 36 native Redis/Valkey topology jobs passed. [46024794058](https://github.com/infocyph/OTP/actions/runs/46024794058): 12 successful jobs, four failures (three analysis jobs and sustained performance), two intentional release/security-report skips. Six QA variants passed including D5, all three standard benchmarks passed, clean install and strict Sphinx build passed. All three PHPStan analyses green; each Psalm log has the same single WeakHash at MobileOTP.php:241. Only that inline review remains open. B-direct, D-direct, E-direct and H-functional verified, without closing their unresolved parent gates.
- [Sustained job 140593416754](https://github.com/infocyph/OTP/actions/runs/46024794058/job/140593416754): generate 1,909,317.96 -> 1,896,801.37 RPM (0.66% regression, pass); roundtrip 1,236,050.72 -> 1,223,740.34 (1.00%, pass); concurrent verify 549,753.09 -> 471,595.63 (baseline spread 8.79%, candidate 0.21%; unstable baseline prevents a valid certified comparison). Prior stable comparison recorded 19.51% concurrent regression. HTTP all trials stable: concurrency 1 improves 15.10%, concurrency 8 regresses 1.70% (pass), concurrency 32 regresses 3.49% (fail). Five-minute soak ran; combined HTTP acceptance failed. Do not represent an unstable baseline or failed HTTP gate as a pass.
- Required upstream actions: CacheLayer 4.1 still lacks an instance-level effective PDO lock capability. Expose the effective lock or native-driver capability and qualify both default SQLite and network PDO; trace historical PostgreSQL lock failure and reproduce the MySQL/MariaDB absent-row full-rollback contention. Foundation 4.0.1 still needs FND-001 dialect-safe schema widening and durable owner/rotation tests. Published releases checked again. Attempted CacheLayer branch creation and dedicated upstream issues in CacheLayer and Foundation; all writes denied HTTP 403 Resource not accessible by integration. No upstream issue/branch was created.
- Remaining product decision: legacy mOTP uses the established MD5 digest; replacing it breaks interop. Retain protocol behavior unless explicit authorization to remove the legacy protocol or narrowly accept the specific security finding is provided. No security gate or detector was weakened. Remaining performance work must retain the original workload, baseline and acceptance budgets. This evidence-only commit does not change application, test or workflow code; final-head checks will be newly scheduled. PR must remain unmerged until all release blockers are closed.

### Batch B6 — recheck absolute expiry after state access

- Latest head aaa6d26: [46028252531](https://github.com/infocyph/OTP/actions/runs/46028252531) passed 36/36 native topology cases; [46028253347](https://github.com/infocyph/OTP/actions/runs/46028253347) passed six functional QA variants, three standard benchmarks, docs, clean install and preparation. Three analysis jobs remain blocked by the legacy MD5 finding; sustained job active at inspection. Published CacheLayer and Foundation remain 4.1 and 4.0.1.
- Source inspection identified stale wall-clock sampling in GenericOtp::verify: a delayed authoritative read or a failed CAS followed by a retry could evaluate a still-present record with the timestamp captured before coordination, admitting an expired proof or calculating its remaining TTL from an obsolete time. Sample time inside the transition callback on each read/retry. Preserve HMAC, public signature, state format, terminal marker, retry budget and fail-closed policy. Added deterministic delayed-read and CAS-contention expiry regressions, plus corrected the GenericOtp guide to describe atomic/lock capability selection and fresh deadline checks. SEC/DATA/FLOW verification pending on new head. No changes to detectors, benchmark workloads or acceptance limits.

### Batch B7 — equivalent implicit expiry semantics for GridOTP and Passkey

- Preceding sustained job [140605128835](https://github.com/infocyph/OTP/actions/runs/46028253347/job/140605128835) confirmed generate 0.67% and roundtrip 1.36% regression (pass), stable concurrent SQLite 303,651.48 -> 199,138.47 RPM (34.42% regression, fail); the HTTP/soak stage was cancelled by B6. Upstream capability blocker persists. B6 hosted checks initiated ([46029199472](https://github.com/infocyph/OTP/actions/runs/46029199472), [46029199166](https://github.com/infocyph/OTP/actions/runs/46029199166)); no final result at inspection.
- Apply the B6 fresh implicit clock rule to GridOTP verification and Passkey registration/authentication completion. Explicit caller timestamps retain their existing semantics; only the default wall clock moves into the transition callback. Added delayed-read regressions using an authentic GridOTP challenge and both Passkey ceremony types, preserving original expiry, terminal deletion policy and existing successful-proof tests. Updated protocol guides. SEC/DATA/COMPAT/FLOW: hosted verification pending; no detector/benchmark changes. Final B6/B7 proof requires green functional checks on the combined head. No claim of full release certification.

### Batch E29 — expiry-regression quality checks

- [46029375449](https://github.com/infocyph/OTP/actions/runs/46029375449) on 48ecf51 completed successfully. [46029375730](https://github.com/infocyph/OTP/actions/runs/46029375730) failed QA PHPCS on four new sleep() calls (GenericOtpTest, AtomicTerminalStateTest, PasskeyTest); Pest passed in the inspected PHP 8.5 lowest job. PHPStan reports Passkey class cognitive complexity 82 (limit 80), and Psalm reports the unchanged legacy MobileOTP WeakHash. Documentation, standard benchmarks, preparation and clean install green at inspection; sustained gate active.
- Use the existing test-only usleep(1_100_000) fixture convention, preserving a delay exceeding one wall-clock second and all expiry/race assertions. Consolidate duplicated Passkey timestamp validation in one private method, explicitly mapping null to zero only for the non-negative validation; implicit clock still sampled after each state read and explicit timestamps unchanged. STRUCT/TYPE/FLOW: no public API, production behavior, security detector or threshold changes. New head hosted verification pending. B6/B7 and E-direct revalidation pending; historical passing evidence remains valid only for its recorded revisions.

### Batch B8 — AOTP signed expiry at consumption

- [46029836697](https://github.com/infocyph/OTP/actions/runs/46029836697) on c80e6b7: 36/36 cluster jobs passed. [46029837301](https://github.com/infocyph/OTP/actions/runs/46029837301): all six QA variants, three standard benchmarks, documentation, preparation and clean install passed, including B6/B7 expiry regressions. PHPStan clean; three Psalm jobs retain the same single legacy MD5 diagnostic. Sustained 2% comparison failed; HTTP stage still running at inspection.
- AOTP previously captured implicit verification time before reservation reads, signature validation and CAS retries; a delayed backend could extend the marker or accept a signed challenge beyond its absolute deadline. Refresh implicit time after signature validation and immediately before the atomic or coordinated mutation. Preserve deterministic explicit timestamps, signed payload, scalar reservation format, failure propagation and retry budget. Added delayed authoritative read regression and documentation. SEC/DATA/COMPAT/FLOW verification pending. No scanner or gate changes.
- CacheLayer 4.1 and Foundation 4.0.1 remain latest published releases, no open upstream PRs at inspection. Prior 403 writes and unresolved capability/schema blockers remain recorded.

### Batch E30 — AOTP reservation-state boundary

- [46031644246](https://github.com/infocyph/OTP/actions/runs/46031644246) on bd71bc3 completed successfully. [46031644802](https://github.com/infocyph/OTP/actions/runs/46031644802): all six functional QA jobs, three standard benchmarks, documentation, clean install and preparation passed, including B8. PHPStan flags AOTP::verifyWithResult cognitive complexity 15 (maximum 12); Psalm retains legacy WeakHash. Sustained gate active at inspection.
- Consolidate the untrusted reservation read and strict validation into one private typed boundary returning only null/0/1. The strict match preserves the previous rejection of booleans, strings and all other invalid values; verification ordering, signed expiry refresh, atomic retry budget and public behavior remain unchanged. STRUCT-01/02, TYPE, SEC and FLOW-02: no detector suppression, gate changes or new classes. Hosted verification pending.

### Batch E31 — AOTP boundary quality corrections

- [46032198358](https://github.com/infocyph/OTP/actions/runs/46032198358) on 07ab432 completed successfully. [46032198714](https://github.com/infocyph/OTP/actions/runs/46032198714): all six QA jobs failed Pint ordered_class_elements and Comment Policy PHPDoc Signature Mismatch at AOTP::reservationState; PHPStan clean and Psalm still flags legacy WeakHash. Documentation, preparation, clean install and standard benchmarks passed. Two AOTP review findings (5301 and 5302) are LessSpecificReturnType and MixedAssignment. Sustained gate still active at inspection.
- Match the untrusted cache result directly and return the exact validated null/0/1 literals. Retain native nullable integer return contract, remove the redundant mismatched PHPDoc, and order private methods alphabetically. Strict rejection of any other value, signed-expiry handling, verification ordering and persistence behavior remain unchanged. TYPE/STRUCT/FLOW-02: no detector or test weakening; hosted verification pending.

### Batch B9 — bounded synchronous Runwire lock acquisition

- [46033284573](https://github.com/infocyph/OTP/actions/runs/46033284573) on ec45da5: 36/36 cluster scenarios passed. [46033284984](https://github.com/infocyph/OTP/actions/runs/46033284984): all six QA variants, all three standard benchmarks, documentation, clean install and preparation passed. E31 AOTP formatting and comment findings resolved; PHPStan clean and Psalm still reports legacy MobileOTP WeakHash; only that inline review remains. Sustained certification running at inspection.
- The synchronous/no-coroutine Runwire lock path previously forwarded the complete OTP wait budget even when the request had a shorter deadline. Apply the existing remaining-deadline calculation before either context-aware acquisition path; preserve the context-free fast path, cooperative zero-wait retries and pre-mutation cancellation/cleanup semantics. Add a bounded-wait regression with a real Runwire request deadline and a recording lock provider. DATA-03/OPS/FLOW: hosted verification pending; underlying I/O still depends on the provider honoring its wait contract.
- CacheLayer 4.1 and Foundation 4.0.1 remain latest; CacheLayer branch creation again returned HTTP 403. No dependency, protocol, quality detector or performance threshold change. Release gates remain open.
