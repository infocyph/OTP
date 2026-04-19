<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Exception;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\OtpMath;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;
use Infocyph\OTP\ValueObjects\VerificationWindow;

final class TOTP
{
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
        if ($period < 1) {
            throw new \InvalidArgumentException('Period must be greater than zero.');
        }

        $this->secret = SecretUtility::normalizeBase32($secret);
    }

    /**
     * @throws Exception
     */
    public static function generateSecret(int $bytes = 64): string
    {
        return SecretUtility::generate($bytes);
    }

    public static function parseProvisioningUri(string $uri): ParsedOtpAuthUri
    {
        return ProvisioningUriParser::parse($uri);
    }

    public function getCurrentTimeStep(?int $timestamp = null): int
    {
        return $this->getTimeStepFromTimestamp($timestamp ?? time());
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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

        return ProvisioningUriBuilder::enrollmentPayload(
            'totp',
            $this->secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            $this->period,
            null,
            null,
            $withQrSvg ? SvgQrRenderer::render($uri, $imageSize) : null,
        );
    }

    public function getOTP(?int $timestamp = null): string
    {
        return OtpMath::hotp(
            $this->secret,
            $this->getTimeStepFromTimestamp($timestamp ?? time()),
            $this->digitCount,
            $this->algorithm,
        );
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'period'],
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'totp',
            $this->secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            $this->period,
        );
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
     * @return array{current:string,next:string,overlapUntil:int|null}
     */
    public function rotateSecret(
        string $newSecret,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
    ): array {
        $now ??= time();

        return [
            'current' => $this->secret,
            'next' => SecretUtility::normalizeBase32($newSecret),
            'overlapUntil' => $gracePeriodInSeconds !== null ? $now + $gracePeriodInSeconds : null,
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
        $this->assertOtp($otp);
        $window ??= new VerificationWindow();
        if ($window->past < 0 || $window->future < 0) {
            throw new \InvalidArgumentException('Verification windows must be non-negative.');
        }

        $baseTimestamp = $timestamp ?? time();
        $currentStep = $this->getTimeStepFromTimestamp($baseTimestamp);
        for ($offset = -$window->past; $offset <= $window->future; $offset++) {
            $matchedStep = $currentStep + $offset;
            if ($matchedStep < 0) {
                continue;
            }

            if (!hash_equals($otp, OtpMath::hotp($this->secret, $matchedStep, $this->digitCount, $this->algorithm))) {
                continue;
            }

            if ($replayStore !== null && $binding !== null && $singleUse) {
                $token = (string) $matchedStep;
                if ($replayStore->hasConsumed('totp:step', $binding, $token)) {
                    return new VerificationResult(false, 'replay', matchedTimestep: $matchedStep, driftOffset: $offset, replayDetected: true);
                }
                $replayStore->markConsumed('totp:step', $binding, $token, $this->period * max(1, $window->past + $window->future + 1));
                $replayStore->setState('totp:last_timestep', $binding, $matchedStep);
            }

            return new VerificationResult(
                true,
                $offset === 0 ? 'matched' : 'drifted',
                matchedTimestep: $matchedStep,
                driftOffset: $offset,
                verifiedAt: new \DateTimeImmutable(),
            );
        }

        return new VerificationResult(false, 'mismatch');
    }

    private function assertOtp(string $otp): void
    {
        if (!preg_match('/^\d+$/', $otp) || strlen($otp) !== $this->digitCount) {
            throw new \InvalidArgumentException('OTP must be a numeric string matching the configured digit count.');
        }
    }
}
