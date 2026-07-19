<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Exception;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\OtpMath;
use Infocyph\OTP\Support\ReplayProtection;
use Infocyph\OTP\Support\SecretRotationPlanner;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\SecretRotation;

final class HOTP extends AbstractOtpAuthenticator
{
    private const int MAX_LOOK_AHEAD = 100;

    private readonly string $binarySecret;

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
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $include, $additionalParameters);

        return $this->buildEnrollmentPayload(
            'hotp',
            $this->secret,
            $label,
            $issuer,
            $include,
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            null,
            $this->counter,
            $withQrSvg,
            $imageSize,
            $uri,
        );
    }

    public function getOTP(int $counter): string
    {
        return OtpMath::hotpFromBinary($this->binarySecret, $counter, $this->digitCount, $this->algorithm);
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
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
    ): string {
        return $this->buildProvisioningUri(
            'hotp',
            $this->secret,
            $label,
            $issuer,
            $include,
            $additionalParameters,
            $this->algorithm,
            $this->digitCount,
            null,
            $this->counter,
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
        array $include = ['algorithm', 'digits', 'counter'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        $rotation = SecretRotationPlanner::prepare($this->secret, $newSecret, $gracePeriodInSeconds, $now);
        $next = new self($rotation['nextSecret'], $this->digitCount);
        $next->setAlgorithm($this->algorithm);
        $next->setCounter($this->counter);

        return new SecretRotation(
            $this->secret,
            $rotation['nextSecret'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
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
        if (!$this->isValidOtp($otp, $this->digitCount)) {
            return new VerificationResult(false, 'malformed');
        }
        self::assertVerificationRange($counter, $lookAhead);
        $this->assertReplayBinding($replayStore, $binding);

        $matchedCounter = $this->findMatchingCounter($otp, $counter, $lookAhead);
        if ($matchedCounter === null) {
            return new VerificationResult(false, 'mismatch');
        }

        if (
            $replayStore !== null
            && $binding !== null
            && $this->isReplay($replayStore, $binding, $matchedCounter)
        ) {
            return new VerificationResult(false, 'replay', matchedCounter: $matchedCounter, replayDetected: true);
        }

        $offset = $matchedCounter - $counter;

        return new VerificationResult(
            true,
            $offset === 0 ? 'matched' : 'resynchronized',
            matchedCounter: $matchedCounter,
            driftOffset: $offset,
            verifiedAt: new \DateTimeImmutable(),
        );
    }

    private static function assertVerificationRange(int $counter, int $lookAhead): void
    {
        if ($counter < 0 || $lookAhead < 0 || $lookAhead > self::MAX_LOOK_AHEAD) {
            throw new \InvalidArgumentException('Counter must be non-negative and look-ahead may not exceed 100.');
        }
        if ($lookAhead > PHP_INT_MAX - $counter) {
            throw new \InvalidArgumentException('Counter and look-ahead window exceed the supported integer range.');
        }
    }

    private function findMatchingCounter(string $otp, int $counter, int $lookAhead): ?int
    {
        for ($offset = 0; $offset <= $lookAhead; $offset++) {
            $matchedCounter = $counter + $offset;
            if (hash_equals($this->getOTP($matchedCounter), $otp)) {
                return $matchedCounter;
            }
        }

        return null;
    }

    private function isReplay(
        ReplayStoreInterface $replayStore,
        string $binding,
        int $matchedCounter,
    ): bool {
        return !ReplayProtection::advance($replayStore, 'hotp:last_counter', $binding, $matchedCounter);
    }
}
