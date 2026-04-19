# Installation

## Requirements

- PHP 8.4 or newer

## Package installation

```bash
composer require infocyph/otp
```

## Documentation toolchain

This project uses Material for MkDocs.

The official Material for MkDocs installation guide recommends installing with `pip`, ideally in a virtual environment, and pinning to the current major version. It also suggests generating a lockfile with `pip freeze` for reproducible builds.

Official reference:

- https://squidfunk.github.io/mkdocs-material/getting-started/

Example setup:

```bash
pip install mkdocs-material=="9.*"
pip freeze > docs/requirements.txt
```

Install from the lockfile:

```bash
pip install -r docs/requirements.txt
```

## Local docs preview

```bash
mkdocs serve
```

## Test suite

```bash
php vendor/bin/pest
```
