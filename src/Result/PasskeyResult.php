<?php

declare(strict_types=1);

namespace Infocyph\OTP\Result;

use Infocyph\OTP\VerificationReason;
use InvalidArgumentException;

final readonly class PasskeyResult
{
    private function __construct(
        public bool $matched,
        public VerificationReason $reason,
        public ?string $credentialId = null,
        #[\SensitiveParameter]
        public ?string $credentialRecordJson = null,
        #[\SensitiveParameter]
        public ?string $userHandle = null,
        public bool $replayDetected = false,
    ) {
        if ($matched && $reason !== VerificationReason::Matched) {
            throw new InvalidArgumentException('Successful passkey results require a matched reason.');
        }
        if (!$matched && $reason === VerificationReason::Matched) {
            throw new InvalidArgumentException('Failed passkey results cannot use a matched reason.');
        }
        if ($matched && ($credentialId === null || $credentialRecordJson === null)) {
            throw new InvalidArgumentException('Successful passkey results require a credential record.');
        }
    }

    /** @return array{matched:bool,reason:string,credentialId:string|null,credentialRecordJson:string|null,userHandle:string|null,replayDetected:bool} */
    public function __debugInfo(): array
    {
        return [
            'matched' => $this->matched,
            'reason' => $this->reason->value,
            'credentialId' => $this->credentialId,
            'credentialRecordJson' => $this->credentialRecordJson === null ? null : '[redacted]',
            'userHandle' => $this->userHandle === null ? null : '[redacted]',
            'replayDetected' => $this->replayDetected,
        ];
    }

    public static function malformed(): self
    {
        return new self(false, VerificationReason::Malformed);
    }

    public static function mismatch(): self
    {
        return new self(false, VerificationReason::Mismatch);
    }

    public static function replay(): self
    {
        return new self(false, VerificationReason::Replay, replayDetected: true);
    }

    public static function success(
        string $credentialId,
        #[\SensitiveParameter]
        string $credentialRecordJson,
        #[\SensitiveParameter]
        ?string $userHandle = null,
    ): self {
        return new self(
            true,
            VerificationReason::Matched,
            $credentialId,
            $credentialRecordJson,
            $userHandle,
        );
    }
}
