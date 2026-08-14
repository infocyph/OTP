<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\LabelHelper;
use Infocyph\OTP\Support\OtpMath;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\SecretRotationPlanner;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\SecretRotation;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use InvalidArgumentException;

final readonly class TOTP
{
    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_PERIOD = 86400;

    private const string REPLAY_NAMESPACE = 'totp:last_timestep';

    private string $algorithm;

    private string $binarySecret;

    private string $secret;

    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        private int $digits = 6,
        private int $period = 30,
        string $algorithm = 'sha1',
    ) {
        if ($digits < 6 || $digits > 9) {
            throw new InvalidArgumentException('TOTP digit count must be between 6 and 9.');
        }
        if ($period < 1 || $period > self::MAX_PERIOD) {
            throw new InvalidArgumentException('Period must be between 1 and 86400 seconds.');
        }

        $this->secret = SecretUtility::normalizeBase32($secret);
        $this->binarySecret = SecretUtility::requireStrongBase32($this->secret);
        $this->algorithm = AlgorithmValidator::normalize($algorithm);
    }

    public static function generateSecret(int $bytes = 20): string
    {
        return SecretUtility::generate($bytes);
    }

    public function generate(?int $timestamp = null): string
    {
        return OtpMath::hotpFromBinary(
            $this->binarySecret,
            $this->getTimeStepFromTimestamp($timestamp ?? time()),
            $this->digits,
            $this->algorithm,
        );
    }

    public function getCurrentTimeStep(?int $timestamp = null): int
    {
        return $this->getTimeStepFromTimestamp($timestamp ?? time());
    }

    /**
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     * @param bool $withQrSvg Whether to render the same URI as an SVG QR code.
     * @param int $imageSize QR image width and height in pixels.
     */
    public function getEnrollmentPayload(
        string $label,
        string $issuer,
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $additionalParameters);

        return new EnrollmentPayload(
            $this->secret,
            $uri,
            LabelHelper::normalizeIssuer($issuer),
            LabelHelper::normalizeAccountLabel($label),
            $withQrSvg ? SvgQrRenderer::render($uri, $imageSize) : null,
        );
    }

    /**
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'totp',
            $this->secret,
            $label,
            $issuer,
            [
                'algorithm' => $this->algorithm !== 'sha1',
                'digits' => $this->digits !== 6,
                'period' => $this->period !== 30,
            ],
            $additionalParameters,
            $this->algorithm,
            $this->digits,
            $this->period,
        );
    }

    /**
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     * @param int $imageSize QR image width and height in pixels.
     */
    public function getProvisioningUriQR(
        string $label,
        string $issuer,
        array $additionalParameters = [],
        int $imageSize = 200,
    ): string {
        return SvgQrRenderer::render($this->getProvisioningUri($label, $issuer, $additionalParameters), $imageSize);
    }

    public function getRemainingSeconds(?int $timestamp = null): int
    {
        $timestamp ??= time();
        if ($timestamp < 0) {
            throw new InvalidArgumentException('Timestamp must be non-negative.');
        }

        return $this->period - ($timestamp % $this->period);
    }

    public function getTimeStepFromTimestamp(int $timestamp): int
    {
        if ($timestamp < 0) {
            throw new InvalidArgumentException('Timestamp must be non-negative.');
        }

        return intdiv($timestamp, $this->period);
    }

    /**
     * @param string $newSecret Canonical strong Base32 replacement secret.
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param ?int $gracePeriodInSeconds Positive overlap duration; null or zero cuts over immediately.
     * @param ?int $now Optional deterministic Unix timestamp.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     * @param bool $withQrSvg Whether to render the replacement URI as an SVG QR code.
     * @param int $imageSize QR image width and height in pixels.
     */
    public function planRotation(
        #[\SensitiveParameter]
        string $newSecret,
        string $label,
        string $issuer,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        $rotation = SecretRotationPlanner::prepare($this->secret, $newSecret, $gracePeriodInSeconds, $now);
        $next = new self($rotation['nextSecret'], $this->digits, $this->period, $this->algorithm);

        return new SecretRotation(
            $this->secret,
            $rotation['nextSecret'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
            $next->getEnrollmentPayload($label, $issuer, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    public function verify(
        #[\SensitiveParameter]
        string $otp,
        ?int $timestamp = null,
        int $pastWindows = 0,
        int $futureWindows = 0,
    ): bool {
        return $this->verifyWithWindow(
            $otp,
            $timestamp,
            new VerificationWindow($pastWindows, $futureWindows),
        )->matched;
    }

    public function verifyWithWindow(
        #[\SensitiveParameter]
        string $otp,
        ?int $timestamp = null,
        ?VerificationWindow $window = null,
        ?ReplayStoreInterface $replayStore = null,
        ?string $factorId = null,
    ): VerificationResult {
        $window ??= new VerificationWindow();
        self::assertReplayConfiguration($replayStore, $factorId);
        $currentStep = $this->getTimeStepFromTimestamp($timestamp ?? time());
        if (strlen($otp) !== $this->digits || !ctype_digit($otp)) {
            return VerificationResult::malformed();
        }

        $match = $this->findMatch($otp, $currentStep, $window);
        if ($match === null) {
            return VerificationResult::mismatch();
        }

        if ($replayStore !== null && $factorId !== null) {
            $ttl = $this->period * ($window->past + $window->future + 1);
            if (!$replayStore->advance(self::REPLAY_NAMESPACE, $factorId, $match['step'], $ttl)) {
                return VerificationResult::replay($match['step'], driftOffset: $match['offset']);
            }
        }

        return VerificationResult::success(
            $match['offset'] === 0 ? VerificationReason::Matched : VerificationReason::Drifted,
            matchedTimestep: $match['step'],
            driftOffset: $match['offset'],
        );
    }

    private static function assertReplayConfiguration(?ReplayStoreInterface $store, ?string $factorId): void
    {
        if (($store === null) !== ($factorId === null)) {
            throw new InvalidArgumentException('Replay store and factor ID must be provided together.');
        }
        if ($factorId !== null && ($factorId === '' || strlen($factorId) > self::MAX_FACTOR_ID_LENGTH)) {
            throw new InvalidArgumentException('Factor IDs must contain between 1 and 190 bytes.');
        }
    }

    /**
     * @param string $otp Submitted OTP.
     * @param int $currentStep Current moving-factor timestep.
     * @param VerificationWindow $window Accepted past and future drift.
     * @return array{step:int,offset:int}|null
     */
    private function findMatch(string $otp, int $currentStep, VerificationWindow $window): ?array
    {
        if ($this->matches($otp, $currentStep)) {
            return ['step' => $currentStep, 'offset' => 0];
        }

        $maximumDrift = max($window->past, $window->future);
        for ($distance = 1; $distance <= $maximumDrift; $distance++) {
            $pastStep = $currentStep - $distance;
            if ($distance <= $window->past && $pastStep >= 0 && $this->matches($otp, $pastStep)) {
                return ['step' => $pastStep, 'offset' => -$distance];
            }
            if ($distance <= $window->future && $currentStep <= PHP_INT_MAX - $distance && $this->matches($otp, $currentStep + $distance)) {
                return ['step' => $currentStep + $distance, 'offset' => $distance];
            }
        }

        return null;
    }

    private function matches(string $otp, int $step): bool
    {
        return hash_equals(
            OtpMath::hotpFromBinary($this->binarySecret, $step, $this->digits, $this->algorithm),
            $otp,
        );
    }
}
