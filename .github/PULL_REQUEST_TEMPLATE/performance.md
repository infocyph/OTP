## Bottleneck

Describe the measured performance problem, affected execution path and practical impact.

<!--
Link relevant issues, profiles, discussions or reports when available.
-->

## Optimization

Describe the change, why it improves the measured path and any trade-offs introduced.

## Correctness and Compatibility

* [ ] Observable behavior remains unchanged
* [ ] Public API remains compatible
* [ ] Error and exception behavior remains compatible
* [ ] Behavior or public API changed intentionally
* [ ] PHP, extension, platform or dependency requirements changed

<!--
Remove the compatibility notes below when no explanation is required.
-->

## Benchmark Evidence

* [ ] Relevant benchmarks were added or updated
* [ ] Results were compared against a relevant baseline
* [ ] Multiple stable runs were considered
* [ ] Runtime impact was measured
* [ ] Memory or allocation impact was measured where relevant
* [ ] `composer ic:benchmark`
* [ ] `composer ic:bench:quick`
* [ ] `composer ic:bench:chart`

<!--
Environment:
Dataset or workload:
Baseline:
Before:
After:
Difference:
Variance:
-->

## Validation

* [ ] `composer ic:ci`
* [ ] Expected behavior remains covered
* [ ] Boundary and failure paths remain covered
* [ ] Performance-sensitive behavior is covered

<!-- When `composer ic:ci` passes, do not select focused checks. -->

<details>
<summary>Focused validation</summary>

<!--
Use only when `composer ic:ci` was not run or could not complete.
Select every command that passed and explain the limitation below.
-->

* [ ] `composer ic:test:syntax`
* [ ] `composer ic:test:code`
* [ ] `composer ic:test:lint`
* [ ] `composer ic:test:sniff`
* [ ] `composer ic:test:duplicates`
* [ ] `composer ic:test:probe`
* [ ] `composer ic:test:comments`
* [ ] `composer ic:test:architecture`
* [ ] `composer ic:test:static`
* [ ] `composer ic:test:security`
* [ ] `composer ic:test:refactor`

</details>

<!--
Remove the validation notes below when complete validation passed without
limitations.
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight benchmark methodology, hot paths, memory behavior, algorithmic
trade-offs or compatibility risks.
-->

## Checklist

* [ ] The optimization targets a measured bottleneck.
* [ ] Results are reproducible in comparable environments.
* [ ] Correctness was not traded for an unverified micro-optimization.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Benchmark and documentation changes are included where required.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
