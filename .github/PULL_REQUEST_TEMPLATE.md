## Summary

Describe what changed, why it was needed and the expected behavior.

<!--
Link relevant issues, discussions, pull requests or documentation when available.
Use `Closes #...`, `Fixes #...` or `Relates #...` where applicable.
-->

## Change

### Type

* [ ] Bug fix
* [ ] New feature
* [ ] Refactor
* [ ] Performance
* [ ] Security or reliability
* [ ] Documentation or examples
* [ ] Dependency, CI or tooling
* [ ] Other

### Behavior and Compatibility

* [ ] No observable behavior changed
* [ ] Existing behavior was corrected
* [ ] New behavior was introduced
* [ ] Public API or documented behavior changed
* [ ] Backward compatibility may be affected
* [ ] PHP, extension, platform or dependency requirements changed

<!--
Remove the compatibility notes below when no explanation is required.

Describe relevant behavior changes, deprecations, compatibility concerns
or upgrade requirements.
-->

## Validation

* [ ] `composer ic:ci`

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
Remove the validation notes below when `composer ic:ci` passed without
relevant limitations.

Explain skipped or failed checks, environment limitations, manual validation
or other relevant results.
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

## Implementation Notes

<!--
Remove this section when the implementation is straightforward.

Describe important decisions, trade-offs, limitations or intentionally
excluded work.
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight areas that deserve additional reviewer attention.
-->

## Checklist

* [ ] The change is focused and excludes unrelated modifications.
* [ ] Tests cover new, corrected and regression-prone behavior.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Documentation, examples and type information were updated where required.
* [ ] Performance claims are supported by reproducible benchmarks.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
