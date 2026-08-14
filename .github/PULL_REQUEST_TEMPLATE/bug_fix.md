## Problem

Describe the incorrect behavior, its impact and how it can be reproduced.

<!--
Link relevant issues, discussions or reports when available.
Use `Closes #...`, `Fixes #...` or `Relates #...` where applicable.
-->

## Root Cause

<!--
Remove this section when the root cause is unknown or the explanation adds no
review value.

Explain why the problem occurred.
-->

## Fix

Describe how the change corrects the problem and the expected behavior after the fix.

## Behavior and Compatibility

* [ ] Existing documented behavior was restored
* [ ] Existing undocumented behavior was corrected
* [ ] Public API remains compatible
* [ ] Public API or documented behavior changed
* [ ] Backward compatibility may be affected
* [ ] PHP, extension, platform or dependency requirements changed

<!--
Remove the compatibility notes below when no explanation is required.

Describe compatibility concerns, deprecations or upgrade requirements.
-->

## Validation

* [ ] `composer ic:ci`
* [ ] The original failure no longer reproduces
* [ ] A regression test was added or updated
* [ ] Relevant boundary and failure paths were tested

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

Explain skipped checks, environment limitations, manual validation or why a
regression test was not appropriate.
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight the root cause, regression risk, compatibility concern or edge case
that deserves additional attention.
-->

## Checklist

* [ ] The fix is focused and excludes unrelated changes.
* [ ] The fix addresses the root cause rather than only masking symptoms.
* [ ] Regression-prone behavior is covered by tests.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Documentation and examples were updated where required.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
