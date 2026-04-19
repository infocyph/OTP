# Contracts

## ReplayStoreInterface

Use this to persist replay state for TOTP, HOTP, or OCRA verification flows.

## RecoveryCodeStoreInterface

Use this to persist hashed recovery codes and their metadata.

## SecretStoreInterface

Use this when building your own secret storage abstraction around the package.

## Included in-memory stores

- `Infocyph\OTP\Stores\InMemoryReplayStore`
- `Infocyph\OTP\Stores\InMemoryRecoveryCodeStore`
