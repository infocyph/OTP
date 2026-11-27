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

- [ ] A: Runwire ^4.0.1, CacheLayer ^4.1, compatible dependency updates and PHP 8.6 matrix.
- [ ] B: PDO lock ownership and native atomic state.
- [ ] C: Distributed topology and replay.
- [ ] D: Protocol coverage and cross-owner recovery qualification.
- [ ] E: PHPStan (179) and Psalm (940) findings on baseline f40d42e; root-cause fixes, no suppressions.
- [ ] F: Prefer-stable Passkey regression (WebAuthn 5.3.15 baseline).
- [ ] G: Documentation and migration updates.
- [ ] H: Hosted QA, security and sustained performance gates.

Baseline workflow: https://github.com/infocyph/OTP/actions/runs/44992998393 (7 passed, 4 failed, 2 skipped). Findings pending reproduction on updated dependencies. Preserve public contracts and fail-closed semantics. Apply PHPForge CORE, FLOW, SEC, DATA, COMPAT, CONFIG, OPS, PERF and remaining applicable rules with evidence per batch. No automatic merge.

### Batch A — dependency manifest and runtime matrix

- Implemented target constraints: CacheLayer ^4.1, Runwire ^4.0.1, constant-time-encoding ^3.1.5, WebAuthn ^5.3.17. Bacon QR ^3.1.1 is current; PHPForge tracks main. Confirmed published upstream release tags; package resolution and compatibility pending hosted QA.
- Added PHP 8.6 to the QA matrix. Historical Runwire 3 performance baseline remains unchanged intentionally; current candidate uses Runwire 4.
- Updated README and installation guidance. COMPAT/CONFIG/FLOW/PERF verification pending; no change to authentication semantics or performance thresholds.
