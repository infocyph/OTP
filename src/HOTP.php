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
use Infocyph\OTP\ValueObjects\SecretRotation;

final class HOTP
{
    private readonly string $secret;

    private string $algorithm = 'sha1';

    private int $counter = 0;

    public function __construct(
        string $secret,
        private readonly int $digitCount = 6,
    ) {
        if ($digitCount < 4 || $digitCount > 10) {
            throw new \InvalidArgumentException('Digit count must be between 4 and 10.');
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

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function getEnrollmentPayload(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $include, $additionalParameters);

        return ProvisioningUriBuilder::enrollmentPayload(
            'hotp',
            $this->secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            null,
            $this->counter,
            null,
            $withQrSvg ? SvgQrRenderer::render($uri, $imageSize) : null,
        );
    }

    public function getOTP(int $counter): string
    {
        return OtpMath::hotp($this->secret, $counter, $this->digitCount, $this->algorithm);
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'hotp',
            $this->secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            null,
            $this->counter,
        );
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUriQR(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
        int $imageSize = 200,
    ): string {
        return SvgQrRenderer::render(
            $this->getProvisioningUri($label, $issuer, $include, $additionalParameters),
            $imageSize,
        );
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function planSecretRotation(
        string $newSecret,
        string $label,
        string $issuer,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        if ($gracePeriodInSeconds !== null && $gracePeriodInSeconds < 0) {
            throw new \InvalidArgumentException('Grace period must be non-negative.');
        }

        $normalizedSecret = SecretUtility::normalizeBase32($newSecret);
        $next = new self($normalizedSecret, $this->digitCount);
        $next->setAlgorithm($this->algorithm);
        $next->setCounter($this->counter);

        return new SecretRotation(
            $this->secret,
            $normalizedSecret,
            $gracePeriodInSeconds !== null ? new \DateTimeImmutable()->setTimestamp(($now ?? time()) + $gracePeriodInSeconds) : null,
            $next->getEnrollmentPayload($label, $issuer, $include, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    public function setAlgorithm(string $algorithm): static
    {
        $this->algorithm = AlgorithmValidator::normalize($algorithm);

        return $this;
    }

    public function setCounter(int $counter): static
    {
        if ($counter < 0) {
            throw new \InvalidArgumentException('Counter must be non-negative.');
        }

        $this->counter = $counter;

        return $this;
    }

    public function verify(string $otp, int $counter, int $lookAhead = 0): bool
    {
        return $this->verifyWithResult($otp, $counter, $lookAhead)->matched;
    }

    public function verifyWithResult(
        string $otp,
        int $counter,
        int $lookAhead = 0,
        ?ReplayStoreInterface $replayStore = null,
        ?string $binding = null,
    ): VerificationResult {
        $this->assertOtp($otp);
        if ($counter < 0 || $lookAhead < 0) {
            throw new \InvalidArgumentException('Counter and look-ahead window must be non-negative.');
        }

        for ($offset = 0; $offset <= $lookAhead; $offset++) {
            $matchedCounter = $counter + $offset;
            if (!hash_equals($otp, $this->getOTP($matchedCounter))) {
                continue;
            }

            if ($replayStore !== null && $binding !== null) {
                $lastCounter = $replayStore->getState('hotp:last_counter', $binding);
                if (is_int($lastCounter) && $matchedCounter <= $lastCounter) {
                    return new VerificationResult(false, 'replay', matchedCounter: $matchedCounter, replayDetected: true);
                }
                $replayStore->setState('hotp:last_counter', $binding, $matchedCounter);
            }

            return new VerificationResult(
                true,
                $offset === 0 ? 'matched' : 'resynchronized',
                matchedCounter: $matchedCounter,
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
