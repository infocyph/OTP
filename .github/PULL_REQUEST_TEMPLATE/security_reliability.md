<!--
Do not disclose an unpatched vulnerability in a public pull request.
Use GitHub private vulnerability reporting and coordinate through a private
security advisory when confidentiality is required.
-->

## Concern

Describe the security weakness, reliability failure mode or defensive gap being addressed.

<!--
Link only public or disclosure-safe context. Do not expose confidential details.
-->

## Mitigation

Describe how the change reduces the risk and what assumptions or limitations remain.

## Impact and Compatibility

* [ ] Security hardening with no observable behavior change
* [ ] Reliability improvement with no public API change
* [ ] Failure or exception behavior changed
* [ ] Public API or documented behavior changed
* [ ] Backward compatibility may be affected
* [ ] PHP, extension, platform or dependency requirements changed

<!--
Remove the impact notes below when no explanation is required.

Describe threat or failure boundaries, compatibility concerns, residual risk,
deployment considerations or coordinated disclosure status.
-->

## Validation

* [ ] `composer ic:ci`
* [ ] Security-sensitive or failure behavior is covered
* [ ] Abuse, malformed-input or failure paths are covered
* [ ] Regression coverage was added or updated
* [ ] `composer ic:test:security`

<!-- When `composer ic:ci` passes, do not select other focused checks solely to duplicate it. -->

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

Explain skipped checks, test constraints, environment limitations or private
verification that can be safely disclosed.
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight trust boundaries, input handling, failure isolation, sensitive data,
exception behavior or residual risk.
-->

## Checklist

* [ ] Confidential vulnerability details are not exposed publicly.
* [ ] The change is focused and avoids unrelated refactoring.
* [ ] Security or reliability claims are supported by tests.
* [ ] Failure paths and backward-compatibility implications were considered.
* [ ] Documentation and upgrade guidance were updated where required.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `SECURITY.md`, `CONTRIBUTING.md` and the engineering principles.
