# Result Objects

## VerificationResult

Used by advanced verification flows in TOTP, HOTP, and OCRA.

Fields:

- `matched`
- `reason`
- `matchedTimestep`
- `matchedCounter`
- `driftOffset`
- `replayDetected`
- `verifiedAt`

## RecoveryCodeGenerationResult

Fields:

- `plainCodes`
- `totalGenerated`
- `remainingCount`
- `lastUsedAt`

## RecoveryCodeConsumptionResult

Fields:

- `consumed`
- `reason`
- `remainingCount`
- `totalGenerated`
- `lastUsedAt`
