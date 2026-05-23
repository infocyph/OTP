# Contributing

Thanks for contributing.

## Before You Start

- Review the project code of conduct.
- For security issues, use private reporting and avoid opening a public issue.
- Check existing issues and pull requests first to avoid duplicates.

## Local Setup

Requirements:

- See `README.md` for current PHP and Composer requirements.

Install dependencies:

```bash
composer install
```

## Development Workflow

Typical contributor workflow:

1. Create a branch from `main`.
2. Make focused changes.
3. Run quality checks locally.
4. Open a pull request with context and verification notes.

Recommended checks:

```bash
composer ic:tests
```

Useful targeted commands:

```bash
composer ic:test:syntax
composer ic:test:code
composer ic:test:lint
composer ic:test:sniff
composer ic:test:static
composer ic:test:security
composer ic:test:architecture
```

Auto-fix and processing helpers:

```bash
composer ic:process
```

## Pull Request Guidelines

- Keep pull requests scoped to one logical change.
- Include why the change is needed and what behavior changed.
- Add or update tests when behavior changes.
- Update docs when command behavior, config, or workflow behavior changes.
- Ensure CI is green before requesting review.

## Reporting Bugs and Requesting Features

- Use issue templates for bugs, regressions, CI failures, documentation updates, questions, and feature requests.
- Include reproducible steps, expected behavior, and actual behavior.
- Share environment details (PHP version, OS, Composer version).
