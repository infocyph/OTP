# Contributing

Thanks for contributing to this project.

## Before You Start

* Review `CODE_OF_CONDUCT.md`.
* Report security vulnerabilities privately according to `SECURITY.md`.
* Search existing issues and pull requests to avoid duplicate work.
* An issue is not required for small fixes or improvements discovered during development.
* Discuss substantial API, architectural or compatibility changes before implementation.

## Local Setup

Review `README.md` and `composer.json` for supported PHP versions, extensions, dependencies and project-specific requirements.

Install dependencies:

```bash
composer install
```

Inspect the detected PHPForge configuration:

```bash
composer ic:doctor
```

Do not modify files inside `vendor/`.

## Engineering Standards

Before changing or reviewing code, read and follow:

```text
vendor/infocyph/phpforge/resources/engineering-principles.md
```

These principles apply equally to human contributors and automated coding agents. They define the expected approach to implementation decisions, scope control, architecture, performance, security, compatibility, testing and maintainability.

Project-specific requirements may extend these principles but should not silently weaken them.

## Development Workflow

1. Create a branch from the repository’s default branch.
2. Make one focused logical change.
3. Add or update tests for changed behavior.
4. Run relevant focused checks during development.
5. Apply automated processing where appropriate.
6. Review every automatically modified file.
7. Run the complete CI suite before opening a pull request.
8. Add reproducible benchmark evidence for performance-related changes.
9. Complete the pull request template accurately.

## Automated Processing

Run all configured processors:

```bash
composer ic:process
```

Run an individual processor when only a targeted change is needed:

```bash
composer ic:process:refactor
composer ic:process:lint
composer ic:process:sniff
```

Automated processing may modify source files and `composer.json`. Review all resulting changes before committing.

## Validation

Run the complete project validation suite before opening a pull request:

```bash
composer ic:ci
```

When `composer ic:ci` passes, running the same checks individually is unnecessary.

Use focused commands while developing or when the complete suite cannot run:

<details>
<summary>Focused validation commands</summary>

```bash
composer ic:test:syntax
composer ic:test:code
composer ic:test:lint
composer ic:test:sniff
composer ic:test:duplicates
composer ic:test:probe
composer ic:test:comments
composer ic:test:architecture
composer ic:test:static
composer ic:test:security
composer ic:test:refactor
```

</details>

When `composer ic:ci` cannot complete, document:

* Why it could not complete
* Which focused checks passed
* Relevant PHP, dependency, extension or platform limitations
* Any remaining validation risk

Do not suppress, baseline, exclude or weaken a check merely to make validation pass. Any configuration or baseline change must be intentional and explained in the pull request.

## Tests

Test observable behavior and public contracts rather than internal implementation details.

Include relevant coverage for:

* New or corrected behavior
* Regression scenarios
* Boundary and edge cases
* Failure and exception paths
* Public API compatibility
* PHP-version, dependency, extension or platform-sensitive behavior

A bug fix should normally include a regression test that fails without the fix.

## Performance Changes

Run benchmarks when performance is affected or claimed:

```bash
composer ic:benchmark
```

Additional benchmark commands:

```bash
composer ic:bench:quick
composer ic:bench:chart
```

Performance claims must include reproducible before-and-after results from comparable environments. Avoid conclusions based on a single unstable run.

Add or update benchmark coverage when existing benchmarks do not represent the changed execution path.

## Configuration

Inspect the active PHPForge configuration sources:

```bash
composer ic:list-config
composer ic:list-config --json
```

Publish a configuration file only when the project requires rules that differ from PHPForge defaults:

```bash
composer ic:publish-config <file>
```

When changing quality configuration:

* Explain why the current rule is unsuitable
* Keep exclusions narrow
* Avoid weakening checks globally for one change
* Document compatibility or baseline implications

## Pull Request Guidelines

* Keep each pull request limited to one logical change.
* Explain what changed, why it was needed and the expected behavior.
* Identify public API, backward-compatibility, PHP, extension, platform or dependency impacts.
* Select only validation and benchmark checkboxes that reflect work actually performed.
* Add or update tests for behavior changes.
* Update documentation, examples, types and configuration where required.
* Exclude unrelated formatting, refactoring, dependency or generated-file changes.
* Ensure CI passes before requesting review.
* Address review feedback through focused follow-up changes.

Draft pull requests are welcome for incomplete work or early design feedback, but validation claims and checklist items must remain accurate.

## Reporting Bugs and Requesting Features

Use the relevant issue template for bugs, regressions, CI failures, documentation problems, questions and feature requests.

Include when relevant:

* A clear description of the problem or proposed behavior
* A minimal reproduction
* Expected and actual behavior
* Package and dependency versions
* PHP and Composer versions
* Operating system and relevant extensions
* Logs or error output with sensitive information removed

Small, self-contained fixes may be submitted directly as pull requests. Larger behavioral, architectural or compatibility changes should be discussed first.

Security vulnerabilities must not be reported through public issues, discussions or pull requests.
