# Recovery Codes

## Generating codes

```php
use Infocyph\OTP\RecoveryCodes;
use Infocyph\OTP\Stores\InMemoryRecoveryCodeStore;

$codes = new RecoveryCodes(new InMemoryRecoveryCodeStore());

$generated = $codes->generate(
    binding: 'user-42',
    count: 10,
    length: 10,
    groupSize: 4,
);

$generated->plainCodes;
$generated->totalGenerated;
$generated->remainingCount;
```

## Consuming a code

```php
$result = $codes->consume('user-42', $generated->plainCodes[0]);

$result->consumed;
$result->reason;
$result->remainingCount;
$result->lastUsedAt;
```

## Behavior

- codes are displayed in grouped, user-friendly form
- stored values are hashed before persistence
- generating a new set replaces the old set
- a consumed code cannot be reused
