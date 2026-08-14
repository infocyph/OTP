## Intent and Scope

Describe what was restructured, why it was necessary and what remains intentionally unchanged.

<!--
Link relevant issues, discussions or pull requests when available.
Use `Closes #...`, `Fixes #...` or `Relates #...` where applicable.
-->

## Behavioral Guarantee

* [ ] No observable behavior changed
* [ ] Public API remains unchanged
* [ ] Existing behavior was intentionally corrected
* [ ] Public API or documented behavior changed
* [ ] Backward compatibility may be affected

<!--
Remove the behavior notes below when no explanation is required.

Describe intentional behavior changes, compatibility concerns or invariants
preserved by the refactor.
-->

## Design Notes

<!--
Remove this section when the refactor is straightforward.

Describe structural decisions, trade-offs, removed complexity, dependency
direction or intentionally excluded cleanup.
-->

## Validation

* [ ] `composer ic:ci`
* [ ] Existing behavior remains covered
* [ ] Relevant regression and edge cases are covered
* [ ] Public API compatibility was verified

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
Remove this section when no performance change is expected or claimed.
-->

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

Highlight preserved invariants, architectural boundaries, coupling changes or
regression-prone paths.
-->

## Checklist

* [ ] The refactor is focused and excludes unrelated behavior changes.
* [ ] Complexity was reduced without unnecessary abstraction or file growth.
* [ ] Existing contracts and failure behavior remain covered.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Documentation and type information were updated where required.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
