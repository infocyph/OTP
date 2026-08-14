## Maintenance Change

Describe what changed, why it was needed and the expected effect on development, CI or releases.

<!--
Link relevant issues, workflow runs, dependency advisories, discussions or
pull requests when available.
-->

## Category

* [ ] Dependency update
* [ ] CI or workflow change
* [ ] Build or release tooling
* [ ] PHPForge configuration
* [ ] Development tooling
* [ ] Repository maintenance
* [ ] Other

## Impact and Compatibility

* [ ] Runtime behavior is unaffected
* [ ] Development workflow changed
* [ ] CI or release behavior changed
* [ ] Supported PHP, extension, platform or dependency requirements changed
* [ ] Generated files or configuration changed
* [ ] Backward compatibility may be affected

<!--
Remove the impact notes below when no explanation is required.

Describe dependency constraints, workflow permissions, matrix changes,
configuration resolution, upgrade requirements or rollback considerations.
-->

## Validation

* [ ] `composer ic:ci`
* [ ] Relevant workflow or job was exercised
* [ ] Supported matrix or dependency mode was considered
* [ ] Generated or published files were verified
* [ ] Failure and rollback behavior was considered

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

Explain skipped checks, unavailable CI environments or manual verification.
-->

## Review Focus

<!--
Remove this section when no special review focus is required.

Highlight permissions, dependency constraints, configuration precedence,
workflow conditions, generated output or release risk.
-->

## Checklist

* [ ] The change is focused and excludes unrelated source refactoring.
* [ ] Dependency or workflow changes are minimal and justified.
* [ ] Public API and backward-compatibility implications were considered.
* [ ] Documentation and generated files were updated where required.
* [ ] No credentials, secrets, personal data or sensitive debug output are included.
* [ ] I followed `CONTRIBUTING.md` and the engineering principles.
