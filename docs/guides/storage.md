# Storage Guidance

## Secrets

OTP secrets are reversible secrets. If your application must generate future codes, hashing alone is not enough.

## Recovery codes

Recovery codes should usually be stored hashed.

## Replay state

Replay state can live in cache or a database depending on your durability needs.

## Generic OTP

Generic OTP requires a caller-provided PSR-6 cache pool implementation.

## Contracts

The package includes contracts you can implement in your own infrastructure:

- `Infocyph\OTP\Contracts\ReplayStoreInterface`
- `Infocyph\OTP\Contracts\RecoveryCodeStoreInterface`
- `Infocyph\OTP\Contracts\SecretStoreInterface`
