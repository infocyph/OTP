# Benchmarks

The project includes a `phpbench` configuration and a starter benchmark suite under `benchmarks/`.

## Available commands

Run the default aggregate report:

```bash
composer bench:run
```

Run a quicker local iteration:

```bash
composer bench:quick
```

Render the chart-style console report:

```bash
composer bench:chart
```

## What is benchmarked

The starter suite in `benchmarks/OtpBench.php` covers:

- TOTP generation
- TOTP verification
- TOTP verification with replay state
- HOTP generation
- HOTP verification
- OCRA generation
- OCRA verification
- Generic OTP generation
- Generic OTP verification

## Notes

- benchmarks are comparative measurements, not absolute guarantees
- for stable numbers, prefer repeated iterations on a quiet machine
- replay-aware benchmarks create fresh in-memory state for cleaner runs

## Extending the suite

Add more `*Bench.php` files under `benchmarks/`.

The current benchmark config uses:

- `runner.path = benchmarks`
- `runner.file_pattern = *Bench.php`
- attribute-based benchmark discovery
