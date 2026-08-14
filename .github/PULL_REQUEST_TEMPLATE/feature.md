## Motivation

Describe the problem, use case or capability this feature addresses.

<!--
Link relevant issues, discussions, pull requests or documentation when available.
Use `Closes #...`, `Fixes #...` or `Relates #...` where applicable.
-->

## Solution

Describe the proposed behavior and how consumers are expected to use it.

## API and Compatibility

* [ ] No new public API
* [ ] New backward-compatible public API
* [ ] Existing public API or documented behavior changed
* [ ] Backward compatibility may be affected
* [ ] PHP, extension, platform or dependency requirements changed

<!--
Remove the API notes below when no explanation is required.

Describe signatures, contracts, configuration, deprecations, migration needs
or intentionally excluded scope.
-->

## Validation

* [ ] `composer ic:ci`
* [ ] Expected behavior is covered
* [ ] Boundary and edge cases are covered
* [ ] Failure and exception paths are covered
* [ ] Public API usage is covered

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

Explain skipped checks, environment limitations or manual verification.
-->

## Performance

<!--
Remove this section when performance is unaffected and no performance claim
is being made.
-->

* [ ] Relevant benchmarks were added or updated
* [ ] Results were compared against a relevant baseline
* [ ] `composer ic:benchmark`
* [ ] `composer ic:bench:quick`
* [ ] `composer ic:bench:chart`

<!--
Environment:
Baseline:
Before:
After:
Difference:
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight API design, behavior, compatibility, edge cases or trade-offs that
deserve additional attention.
-->

## Checklist

* [ ] The feature is focused and excludes unrelated changes.
* [ ] Tests cover the public contract and failure behavior.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Documentation, examples and type information were updated.
* [ ] Performance claims are supported by reproducible benchmarks.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
