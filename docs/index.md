# OTP

Standalone OTP and MFA primitives for PHP.

## What this library includes

- TOTP (RFC6238)
- HOTP (RFC4226)
- OCRA (RFC6287)
- Generic OTP backed by PSR-6 cache storage
- Recovery and backup codes
- Replay protection contracts and in-memory stores
- `otpauth://` generation and parsing

## Why this package

This package aims to cover the practical OTP and MFA building blocks that applications usually need, without turning into a full authentication framework.

It gives you:

- simple boolean verification methods when that is enough
- richer result objects when you need drift, replay, or matched-step details
- provisioning helpers for authenticators
- pluggable storage contracts for replay state and recovery codes

## Start here

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Migration Notes](getting-started/migration.md)

## Main guides

- [TOTP](guides/totp.md)
- [HOTP](guides/hotp.md)
- [Generic OTP](guides/generic-otp.md)
- [OCRA](guides/ocra.md)
- [Provisioning](guides/provisioning.md)
- [Replay Protection](guides/replay-protection.md)
- [Recovery Codes](guides/recovery-codes.md)
- [Benchmarks](guides/benchmarks.md)
- [Storage Guidance](guides/storage.md)

## Reference

- [Result Objects](api/results.md)
- [Support Layer](api/support.md)
- [Contracts](api/contracts.md)
