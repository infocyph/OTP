<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Exception;
use Infocyph\OTP\Contracts\AtomicReplayStoreInterface;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\OtpMath;
use Infocyph\OTP\Support\SecretRotationPlanner;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\SecretRotation;
use Infocyph\OTP\ValueObjects\VerificationWindow;

final class TOTP extends AbstractOtpAuthenticator
{
    private const int MAX_PERIOD = 86400;

    private readonly string $binarySecret;

    private readonly string $secret;

    private string $algorithm = 'sha1';

    public function __construct(
        string $secret,
        private readonly int $digitCount = 6,
        private readonly int $period = 30,
    ) {
        if ($digitCount < 4 || $digitCount > 10) {
            throw new \InvalidArgumentException('Digit count must be between 4 and 10.');
        }
        if ($period < 1 || $period > self::MAX_PERIOD) {
            throw new \InvalidArgumentException('Period must be between 1 and 86400 seconds.');
        }

        $this->secret = SecretUtility::normalizeBase32($secret);
        $this->binarySecret = SecretUtility::decodeBase32($this->secret);
    }

    /**
     * @param $bytes Secret byte length.
     * @throws Exception
     */
    public static function generateSecret(int $bytes = 64): string
    {
        return SecretUtility::generate($bytes);
    }

    public function getCurrentTimeStep(?int $timestamp = null): int
    {
        return $this->getTimeStepFromTimestamp($timestamp ?? time());
    }

    /**
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $withQrSvg Whether to render QR SVG.
     * @param $imageSize QR image size.
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public function getEnrollmentPayload(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $include, $additionalParameters);

        return $this->buildEnrollmentPayload(
            'totp',
            $this->secret,
            $label,
            $issuer,
            $include,
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            $this->period,
            null,
            $withQrSvg,
            $imageSize,
            $uri,
        );
    }

    public function getOTP(?int $timestamp = null): string
    {
        return OtpMath::hotpFromBinary(
            $this->binarySecret,
            $this->getTimeStepFromTimestamp($timestamp ?? time()),
            $this->digitCount,
            $this->algorithm,
        );
    }

    /**
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period'],
        array $additionalParameters = [],
    ): string {
        return $this->buildProvisioningUri(
            'totp',
            $this->secret,
            $label,
            $issuer,
            $include,
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            $this->period,
            null,
        );
    }

    /**
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $imageSize QR image size.
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUriQR(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period'],
        array $additionalParameters = [],
        int $imageSize = 200,
    ): string {
        return SvgQrRenderer::render(
            $this->getProvisioningUri($label, $issuer, $include, $additionalParameters),
            $imageSize,
        );
    }

    public function getRemainingSeconds(?int $timestamp = null): int
    {
        $timestamp ??= time();
        if ($timestamp < 0) {
            throw new \InvalidArgumentException('Timestamp must be non-negative.');
        }

        return $this->period - ($timestamp % $this->period);
    }

    public function getTimeStepFromTimestamp(int $timestamp): int
    {
        if ($timestamp < 0) {
            throw new \InvalidArgumentException('Timestamp must be non-negative.');
        }

        return intdiv($timestamp, $this->period);
    }

    /**
     * @param $newSecret Replacement Base32 secret.
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $gracePeriodInSeconds Optional overlap duration.
     * @param $now Current timestamp override.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $withQrSvg Whether to render QR SVG.
     * @param $imageSize QR image size.
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    public function planSecretRotation(
        string $newSecret,
        string $label,
        string $issuer,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
        array $include = ['algorithm', 'digits', 'period'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        $rotation = $this->rotateSecret($newSecret, $gracePeriodInSeconds, $now);
        $next = new self($rotation['next'], $this->digitCount, $this->period);
        $next->setAlgorithm($this->algorithm);

        return new SecretRotation(
            $rotation['current'],
            $rotation['next'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
            $next->getEnrollmentPayload($label, $issuer, $include, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    /**
     * @param $newSecret Replacement Base32 secret.
     * @param $gracePeriodInSeconds Optional overlap duration.
     * @param $now Current timestamp override.
     * @return array Rotation metadata.
     * @phpstan-return array{current:string,next:string,overlapUntil:int|null}
     */
    public function rotateSecret(
        string $newSecret,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
    ): array {
        $rotation = SecretRotationPlanner::prepare($this->secret, $newSecret, $gracePeriodInSeconds, $now);

        return [
            'current' => $this->secret,
            'next' => $rotation['nextSecret'],
            'overlapUntil' => $rotation['overlapUntil'],
        ];
    }

    public function setAlgorithm(string $algorithm): static
    {
        $this->algorithm = AlgorithmValidator::normalize($algorithm);

        return $this;
    }

    public function verify(
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
        string $otp,
        ?int $timestamp = null,
        ?VerificationWindow $window = null,
        ?ReplayStoreInterface $replayStore = null,
        ?string $binding = null,
        bool $singleUse = true,
    ): VerificationResult {
        if (!$this->isValidOtp($otp, $this->digitCount)) {
            return new VerificationResult(false, 'malformed');
        }
        $window ??= new VerificationWindow();
        $this->assertReplayBinding($replayStore, $binding);

        $baseTimestamp = $timestamp ?? time();
        $currentStep = $this->getTimeStepFromTimestamp($baseTimestamp);
        $match = $this->findMatch($otp, $currentStep, $window);
        if ($match === null) {
            return new VerificationResult(false, 'mismatch');
        }

        if (
            $replayStore !== null
            && $binding !== null
            && $singleUse
            && $this->isReplay($replayStore, $binding, $match['step'], $window)
        ) {
            return new VerificationResult(false, 'replay', matchedTimestep: $match['step'], driftOffset: $match['offset'], replayDetected: true);
        }

        return new VerificationResult(
            true,
            $match['offset'] === 0 ? 'matched' : 'drifted',
            matchedTimestep: $match['step'],
            driftOffset: $match['offset'],
            verifiedAt: new \DateTimeImmutable(),
        );
    }

    /**
     * @param $otp Submitted OTP.
     * @param $currentStep Current TOTP step.
     * @param $window Allowed verification window.
     * @return array|null Matched step and drift offset.
     * @phpstan-return array{step:int,offset:int}|null
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

    private function isReplay(
        ReplayStoreInterface $replayStore,
        string $binding,
        int $matchedStep,
        VerificationWindow $window,
    ): bool {
        $token = (string) $matchedStep;
        $ttl = $this->period * ($window->past + $window->future + 1);
        if ($replayStore instanceof AtomicReplayStoreInterface) {
            $consumed = $replayStore->consumeOnce('totp:step', $binding, $token, $ttl);
        } else {
            $consumed = !$replayStore->hasConsumed('totp:step', $binding, $token);
            if ($consumed) {
                $replayStore->markConsumed('totp:step', $binding, $token, $ttl);
            }
        }

        if (!$consumed) {
            return true;
        }

        $replayStore->setState('totp:last_timestep', $binding, $matchedStep);

        return false;
    }

    private function matches(string $otp, int $step): bool
    {
        return hash_equals(
            OtpMath::hotpFromBinary($this->binarySecret, $step, $this->digitCount, $this->algorithm),
            $otp,
        );
    }
}
