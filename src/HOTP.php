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
use InvalidArgumentException;

final readonly class HOTP
{
    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_LOOK_AHEAD = 100;

    private const string REPLAY_NAMESPACE = 'hotp:last_counter';

    private string $algorithm;

    private string $binarySecret;

    private string $secret;

    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        private int $digits = 6,
        string $algorithm = 'sha1',
    ) {
        if ($digits < 6 || $digits > 9) {
            throw new InvalidArgumentException('HOTP digit count must be between 6 and 9.');
        }

        $this->secret = SecretUtility::normalizeBase32($secret);
        $this->binarySecret = SecretUtility::requireStrongBase32($this->secret);
        $this->algorithm = AlgorithmValidator::normalize($algorithm);
    }

    public static function generateSecret(int $bytes = 20): string
    {
        return SecretUtility::generate($bytes);
    }

    public function generate(int $counter): string
    {
        return OtpMath::hotpFromBinary($this->binarySecret, $counter, $this->digits, $this->algorithm);
    }

    /**
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param int $initialCounter Initial non-negative HOTP counter.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     * @param bool $withQrSvg Whether to render the same URI as an SVG QR code.
     * @param int $imageSize QR image width and height in pixels.
     */
    public function getEnrollmentPayload(
        string $label,
        string $issuer,
        int $initialCounter = 0,
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $initialCounter, $additionalParameters);

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
     * @param int $initialCounter Initial non-negative HOTP counter.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        int $initialCounter = 0,
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'hotp',
            $this->secret,
            $label,
            $issuer,
            [
                'algorithm' => $this->algorithm !== 'sha1',
                'digits' => $this->digits !== 6,
                'counter' => true,
            ],
            $additionalParameters,
            $this->algorithm,
            $this->digits,
            null,
            $initialCounter,
        );
    }

    /**
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param int $initialCounter Initial non-negative HOTP counter.
     * @param array<string, scalar|null> $additionalParameters Non-reserved provisioning extensions.
     * @param int $imageSize QR image width and height in pixels.
     */
    public function getProvisioningUriQR(
        string $label,
        string $issuer,
        int $initialCounter = 0,
        array $additionalParameters = [],
        int $imageSize = 200,
    ): string {
        return SvgQrRenderer::render(
            $this->getProvisioningUri($label, $issuer, $initialCounter, $additionalParameters),
            $imageSize,
        );
    }

    /**
     * @param string $newSecret Canonical strong Base32 replacement secret.
     * @param string $label Account label without an issuer prefix.
     * @param string $issuer Issuer name; colons are not allowed.
     * @param int $initialCounter Initial counter for the replacement secret.
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
        int $initialCounter = 0,
        ?int $gracePeriodInSeconds = null,
        ?int $now = null,
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        $rotation = SecretRotationPlanner::prepare($this->secret, $newSecret, $gracePeriodInSeconds, $now);
        $next = new self($rotation['nextSecret'], $this->digits, $this->algorithm);

        return new SecretRotation(
            $this->secret,
            $rotation['nextSecret'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
            $next->getEnrollmentPayload(
                $label,
                $issuer,
                $initialCounter,
                $additionalParameters,
                $withQrSvg,
                $imageSize,
            ),
        );
    }

    public function verify(#[\SensitiveParameter] string $otp, int $counter, int $lookAhead = 0): bool
    {
        return $this->verifyWithResult($otp, $counter, $lookAhead)->matched;
    }

    public function verifyWithResult(
        #[\SensitiveParameter]
        string $otp,
        int $counter,
        int $lookAhead = 0,
        ?ReplayStoreInterface $replayStore = null,
        ?string $factorId = null,
    ): VerificationResult {
        self::assertVerificationConfiguration($counter, $lookAhead, $replayStore, $factorId);
        if (strlen($otp) !== $this->digits || !ctype_digit($otp)) {
            return VerificationResult::malformed();
        }

        $matchedCounter = $this->findMatchingCounter($otp, $counter, $lookAhead);
        if ($matchedCounter === null) {
            return VerificationResult::mismatch();
        }
        if ($replayStore !== null && $factorId !== null && !$replayStore->advance(self::REPLAY_NAMESPACE, $factorId, $matchedCounter)) {
            return VerificationResult::replay(matchedCounter: $matchedCounter);
        }

        $offset = $matchedCounter - $counter;

        return VerificationResult::success(
            $offset === 0 ? VerificationReason::Matched : VerificationReason::Resynchronized,
            matchedCounter: $matchedCounter,
            nextCounter: $matchedCounter < PHP_INT_MAX ? $matchedCounter + 1 : null,
            driftOffset: $offset,
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

    private static function assertVerificationConfiguration(
        int $counter,
        int $lookAhead,
        ?ReplayStoreInterface $replayStore,
        ?string $factorId,
    ): void {
        if ($counter < 0 || $lookAhead < 0 || $lookAhead > self::MAX_LOOK_AHEAD) {
            throw new InvalidArgumentException('Counter must be non-negative and look-ahead may not exceed 100.');
        }
        if ($lookAhead > PHP_INT_MAX - $counter) {
            throw new InvalidArgumentException('Counter and look-ahead exceed the supported integer range.');
        }
        self::assertReplayConfiguration($replayStore, $factorId);
    }

    private function findMatchingCounter(string $otp, int $counter, int $lookAhead): ?int
    {
        for ($offset = 0; $offset <= $lookAhead; $offset++) {
            $candidate = $counter + $offset;
            if (hash_equals($this->generate($candidate), $otp)) {
                return $candidate;
            }
        }

        return null;
    }
}
