<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\Support\LabelHelper;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\SecretRotationPlanner;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\OcraSuite;
use Infocyph\OTP\ValueObjects\SecretRotation;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;
use RuntimeException;

final readonly class OCRA
{
    private const int MAX_FACTOR_ID_LENGTH = 190;

    private string $base32Secret;

    private OcraSuite $suite;

    public function __construct(string $suite, #[\SensitiveParameter] private string $sharedKey)
    {
        if (strlen($sharedKey) < 16 || strlen($sharedKey) > 1024) {
            throw new InvalidArgumentException('OCRA shared keys must contain between 16 and 1024 bytes.');
        }

        $this->suite = OcraSuite::parse($suite);
        $this->base32Secret = rtrim(Base32::encodeUpper($sharedKey), '=');
    }

    public static function fromBase32(string $suite, #[\SensitiveParameter] string $secret): self
    {
        return new self($suite, SecretUtility::requireStrongBase32($secret));
    }

    public static function generateSecret(int $bytes = 20): string
    {
        return SecretUtility::generate($bytes);
    }

    public static function sessionHex(#[\SensitiveParameter] string $hex): string
    {
        if ($hex === '' || !ctype_xdigit($hex)) {
            throw new InvalidArgumentException('Hexadecimal session input must be non-empty.');
        }

        $session = self::hexToBytes($hex);
        if (preg_match('//u', $session) !== 1) {
            throw new InvalidArgumentException('Hexadecimal session input must decode to valid UTF-8.');
        }

        return $session;
    }

    public function generate(
        string $challenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
    ): string {
        $operation = $this->prepareOperation($challenge, $counter, $pin, $session, $timestamp);

        return $this->calculate($challenge, $operation);
    }

    public function generateMutual(
        string $clientChallenge,
        string $serverChallenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
    ): string {
        $challenge = $this->composeChallenge($clientChallenge, $serverChallenge);
        $operation = $this->prepareOperation($challenge, $counter, $pin, $session, $timestamp, true);

        return $this->calculate($challenge, $operation);
    }

    public function generateSignature(
        string $signatureChallenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
    ): string {
        $operation = $this->prepareOperation($signatureChallenge, $counter, $pin, $session, $timestamp);

        return $this->calculate($signatureChallenge, $operation);
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
            $this->base32Secret,
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
    public function getProvisioningUri(string $label, string $issuer, array $additionalParameters = []): string
    {
        return ProvisioningUriBuilder::build(
            'ocra',
            $this->base32Secret,
            $label,
            $issuer,
            ['algorithm' => true, 'digits' => true],
            $additionalParameters,
            $this->suite->algorithm,
            $this->suite->digits,
            ocraSuite: $this->suite->suite,
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

    public function getSuite(): OcraSuite
    {
        return $this->suite;
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
        $rotation = SecretRotationPlanner::prepare(
            $this->base32Secret,
            $newSecret,
            $gracePeriodInSeconds,
            $now,
        );
        $next = self::fromBase32($this->suite->suite, $rotation['nextSecret']);

        return new SecretRotation(
            $this->base32Secret,
            $rotation['nextSecret'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
            $next->getEnrollmentPayload($label, $issuer, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    public function verify(
        #[\SensitiveParameter]
        string $otp,
        string $challenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
        ?VerificationWindow $timeWindow = null,
    ): bool {
        return $this->verifyWithResult(
            $otp,
            $challenge,
            $counter,
            $pin,
            $session,
            $timestamp,
            $timeWindow,
        )->matched;
    }

    public function verifyMutual(
        #[\SensitiveParameter]
        string $otp,
        string $clientChallenge,
        string $serverChallenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
        ?VerificationWindow $timeWindow = null,
    ): bool {
        $challenge = $this->composeChallenge($clientChallenge, $serverChallenge);

        return $this->verifyChallenge(
            $otp,
            $challenge,
            $counter,
            $pin,
            $session,
            $timestamp,
            $timeWindow,
            composite: true,
        )->matched;
    }

    public function verifyWithResult(
        #[\SensitiveParameter]
        string $otp,
        string $challenge,
        ?int $counter = null,
        #[\SensitiveParameter]
        ?string $pin = null,
        #[\SensitiveParameter]
        ?string $session = null,
        ?int $timestamp = null,
        ?VerificationWindow $timeWindow = null,
        ?AuthenticationStateCacheInterface $cache = null,
        ?string $factorId = null,
        ?int $replayTtl = null,
    ): VerificationResult {
        return $this->verifyChallenge(
            $otp,
            $challenge,
            $counter,
            $pin,
            $session,
            $timestamp,
            $timeWindow,
            $cache,
            $factorId,
            $replayTtl,
        );
    }

    private static function assertReplayConfiguration(
        ?AuthenticationStateCacheInterface $cache,
        ?string $factorId,
        ?int $ttl,
    ): void {
        if (($cache === null) !== ($factorId === null)) {
            throw new InvalidArgumentException('CacheLayer authentication state cache and factor ID must be provided together.');
        }
        if ($factorId !== null && ($factorId === '' || strlen($factorId) > self::MAX_FACTOR_ID_LENGTH)) {
            throw new InvalidArgumentException('Factor IDs must contain between 1 and 190 bytes.');
        }
        if ($ttl !== null && $ttl < 1) {
            throw new InvalidArgumentException('OCRA replay TTL must be positive.');
        }
        if ($cache === null && $ttl !== null) {
            throw new InvalidArgumentException('OCRA replay TTL requires CacheLayer replay protection.');
        }
        if ($cache !== null) {
            CacheLock::assertSafe($cache);
        }
    }

    private static function decimalToBinary(string $decimal): string
    {
        $decimal = ltrim($decimal, '0');
        if ($decimal === '') {
            return "\0";
        }

        $hex = '';
        while ($decimal !== '') {
            $quotient = '';
            $remainder = 0;
            $length = strlen($decimal);
            for ($index = 0; $index < $length; $index++) {
                $value = ($remainder * 10) + (ord($decimal[$index]) - 48);
                $digit = intdiv($value, 16);
                if ($quotient !== '' || $digit !== 0) {
                    $quotient .= (string) $digit;
                }
                $remainder = $value % 16;
            }

            $hex = dechex($remainder) . $hex;
            $decimal = $quotient;
        }

        return self::hexToBytes($hex);
    }

    private static function hexToBytes(string $hex): string
    {
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }

        $bytes = hex2bin($hex);
        if ($bytes === false) {
            throw new InvalidArgumentException('Invalid hexadecimal input.');
        }

        return $bytes;
    }

    private static function packInteger(int $value): string
    {
        return pack('NN', ($value >> 32) & 0xFFFFFFFF, $value & 0xFFFFFFFF);
    }

    private function advanceCounter(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        int $counter,
    ): bool {
        $stateKey = hash('sha256', "infocyph:otp:ocra:counter:v1\0" . $factorId);
        $lockKey = hash('sha256', "infocyph:otp:ocra:counter-lock:v1\0" . $factorId);

        return CacheLock::advance($cache, $stateKey, $lockKey, $counter, null, 'OCRA counter');
    }

    private function assertChallenge(string $challenge, bool $composite = false): void
    {
        $length = $composite ? 128 : $this->suite->challengeLength;
        $valid = match ($this->suite->challengeFormat) {
            'n' => preg_match('/^\d{1,' . $length . '}$/', $challenge) === 1,
            'a' => preg_match('/^[A-Za-z0-9]{1,' . $length . '}$/', $challenge) === 1,
            'h' => preg_match('/^[A-Fa-f0-9]{1,' . $length . '}$/', $challenge) === 1,
            default => false,
        };
        if (!$valid) {
            throw new InvalidArgumentException('Challenge does not match the OCRA suite format and length.');
        }
    }

    private function assertCounterInput(?int $counter): void
    {
        if ($this->suite->counterEnabled !== ($counter !== null) || ($counter !== null && $counter < 0)) {
            throw new InvalidArgumentException('Counter input must be supplied exactly when the OCRA suite contains C.');
        }
    }

    private function assertPinInput(?string $pin): void
    {
        if ($this->suite->usesPin() !== ($pin !== null) || ($pin !== null && ($pin === '' || strlen($pin) > 1024))) {
            throw new InvalidArgumentException('PIN input must be supplied exactly when the OCRA suite contains P.');
        }
    }

    private function assertSessionInput(?string $session): void
    {
        if ($this->suite->usesSession() !== ($session !== null)) {
            throw new InvalidArgumentException('Session input must be supplied exactly when the OCRA suite contains S.');
        }
        if ($session !== null && ($session === '' || preg_match('//u', $session) !== 1 || strlen($session) > $this->suite->sessionLength)) {
            throw new InvalidArgumentException('Session must be valid UTF-8 within the suite byte length.');
        }
    }

    private function assertTimestampInput(?int $timestamp): void
    {
        if ($this->suite->usesTime() !== ($timestamp !== null) || ($timestamp !== null && $timestamp < 0)) {
            throw new InvalidArgumentException('Timestamp input must be supplied exactly when the OCRA suite contains T.');
        }
    }

    private function assertVerificationWindow(
        VerificationWindow $window,
        ?AuthenticationStateCacheInterface $cache,
        ?string $factorId,
        ?int $replayTtl,
    ): void {
        self::assertReplayConfiguration($cache, $factorId, $replayTtl);
        if (!$this->suite->usesTime() && ($window->past !== 0 || $window->future !== 0)) {
            throw new InvalidArgumentException('OCRA time windows require a suite containing T.');
        }
        if ($cache !== null && $this->suite->counterEnabled && $replayTtl !== null) {
            throw new InvalidArgumentException('Counter-based OCRA replay state must not expire.');
        }
        if ($cache !== null && !$this->suite->counterEnabled && $replayTtl === null) {
            throw new InvalidArgumentException('Non-counter OCRA replay protection requires a positive replay TTL.');
        }
        if ($replayTtl === null || $this->suite->timeStepSeconds === null) {
            return;
        }

        $minimumTtl = $this->suite->timeStepSeconds * ($window->past + $window->future + 1);
        if ($replayTtl < $minimumTtl) {
            throw new InvalidArgumentException('OCRA replay TTL does not cover the complete time acceptance window.');
        }
    }

    /**
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     */
    private function buildMessage(string $challenge, array $operation): string
    {
        $message = $this->suite->suite . "\0";
        if ($operation['counter'] !== null) {
            $message .= self::packInteger($operation['counter']);
        }
        $message .= $this->encodeChallenge($challenge);
        $message .= $operation['pinDigest'] ?? '';
        $message .= $operation['session'] ?? '';
        if ($operation['timestamp'] !== null && $this->suite->timeStepSeconds !== null) {
            $message .= self::packInteger(intdiv($operation['timestamp'], $this->suite->timeStepSeconds));
        }

        return $message;
    }

    /**
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     */
    private function calculate(string $challenge, array $operation): string
    {
        $hash = hash_hmac($this->suite->algorithm, $this->buildMessage($challenge, $operation), $this->sharedKey, true);
        if ($this->suite->digits === 0) {
            return strtoupper(bin2hex($hash));
        }

        $offset = ord($hash[-1]) & 0x0F;
        $unpacked = unpack('Nvalue', substr($hash, $offset, 4));
        if ($unpacked === false || !is_int($unpacked['value'])) {
            throw new RuntimeException('Unable to calculate OCRA output.');
        }
        $modulus = match ($this->suite->digits) {
            4 => 10_000,
            5 => 100_000,
            6 => 1_000_000,
            7 => 10_000_000,
            8 => 100_000_000,
            9 => 1_000_000_000,
            default => throw new RuntimeException('Invalid parsed OCRA digit count.'),
        };

        return str_pad(
            (string) (($unpacked['value'] & 0x7FFFFFFF) % $modulus),
            $this->suite->digits,
            '0',
            STR_PAD_LEFT,
        );
    }

    private function composeChallenge(string $first, string $second): string
    {
        $this->assertChallenge($first);
        $this->assertChallenge($second);
        if (strlen($first . $second) > 128) {
            throw new InvalidArgumentException('Composite OCRA challenges cannot exceed 128 bytes.');
        }

        return $first . $second;
    }

    private function consumeMessage(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        string $message,
        int $ttl,
    ): bool {
        $stateKey = hash('sha256', "infocyph:otp:ocra:message:v1\0" . $factorId . "\0" . $message);
        $lockKey = hash('sha256', "infocyph:otp:ocra:message-lock:v1\0" . $factorId . "\0" . $message);

        return CacheLock::consumeOnce($cache, $stateKey, $lockKey, $ttl, 'OCRA replay');
    }

    private function encodeChallenge(string $challenge): string
    {
        $bytes = match ($this->suite->challengeFormat) {
            'n' => self::decimalToBinary($challenge),
            'a' => $challenge,
            'h' => self::hexToBytes($challenge),
            default => throw new RuntimeException('Invalid parsed OCRA challenge format.'),
        };

        return str_pad($bytes, 128, "\0");
    }

    /**
     * @param string $otp Submitted OCRA output.
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     * @param VerificationWindow $window Accepted past and future drift.
     * @param int $timestamp Current operation timestamp.
     * @param int $timeStep Parsed suite timestep in seconds.
     * @return array{message:string,offset:int}|null
     */
    private function findDriftMatch(
        string $otp,
        string $challenge,
        array $operation,
        VerificationWindow $window,
        int $timestamp,
        int $timeStep,
    ): ?array {
        $maximumDrift = max($window->past, $window->future);
        for ($distance = 1; $distance <= $maximumDrift; $distance++) {
            if ($distance <= $window->past && $timestamp >= $distance * $timeStep) {
                $past = $this->matchTimeOffset($otp, $challenge, $operation, -$distance);
                if ($past !== null) {
                    return $past;
                }
            }
            if ($distance <= $window->future && $timestamp <= PHP_INT_MAX - ($distance * $timeStep)) {
                $future = $this->matchTimeOffset($otp, $challenge, $operation, $distance);
                if ($future !== null) {
                    return $future;
                }
            }
        }

        return null;
    }

    /**
     * @param string $otp Submitted OCRA output.
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     * @param VerificationWindow $window Accepted past and future drift.
     * @return array{message:string,offset:int}|null
     */
    private function findTimeMatch(
        string $otp,
        string $challenge,
        array $operation,
        VerificationWindow $window,
    ): ?array {
        $timestamp = $operation['timestamp'];
        $timeStep = $this->suite->timeStepSeconds;
        if ($timestamp === null || $timeStep === null) {
            return $this->matchTimeOffset($otp, $challenge, $operation, 0);
        }

        $exact = $this->matchTimeOffset($otp, $challenge, $operation, 0);
        if ($exact !== null) {
            return $exact;
        }

        return $this->findDriftMatch($otp, $challenge, $operation, $window, $timestamp, $timeStep);
    }

    private function isReplay(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        int $counter,
        string $message,
        ?int $ttl,
    ): bool {
        if ($this->suite->counterEnabled) {
            return !$this->advanceCounter($cache, $factorId, $counter);
        }

        return !$this->consumeMessage($cache, $factorId, $message, $ttl ?? 0);
    }

    /**
     * @param string $otp Submitted OCRA output.
     * @param string $challenge Validated operation challenge.
     * @param array{counter:?int,pinDigest:?string,session:?string,timestamp:?int} $operation
     * @param int $offset Candidate timestep offset.
     * @return array{message:string,offset:int}|null
     */
    private function matchTimeOffset(string $otp, string $challenge, array $operation, int $offset): ?array
    {
        if ($offset !== 0) {
            $timestamp = $operation['timestamp'] ?? throw new RuntimeException('Missing OCRA timestamp.');
            $timeStep = $this->suite->timeStepSeconds ?? throw new RuntimeException('Missing OCRA time step.');
            $operation['timestamp'] = $timestamp + ($offset * $timeStep);
        }
        if (!hash_equals($this->calculate($challenge, $operation), $otp)) {
            return null;
        }

        return ['message' => $this->buildMessage($challenge, $operation), 'offset' => $offset];
    }

    /**
     * @param string $challenge Caller-supplied challenge.
     * @param ?int $counter Suite counter input.
     * @param ?string $pin Suite PIN input.
     * @param ?string $session Suite session input.
     * @param ?int $timestamp Suite timestamp input.
     * @param bool $composite Whether the challenge was explicitly composed for mutual authentication.
     * @return array{counter:?int,pinDigest:?string,session:?string,timestamp:?int}
     */
    private function prepareOperation(
        string $challenge,
        ?int $counter,
        #[\SensitiveParameter]
        ?string $pin,
        #[\SensitiveParameter]
        ?string $session,
        ?int $timestamp,
        bool $composite = false,
    ): array {
        $this->assertChallenge($challenge, $composite);
        $this->assertCounterInput($counter);
        $this->assertPinInput($pin);
        $this->assertSessionInput($session);
        $this->assertTimestampInput($timestamp);

        return [
            'counter' => $counter,
            'pinDigest' => $pin !== null && $this->suite->pinAlgorithm !== null
                ? hash($this->suite->pinAlgorithm, $pin, true)
                : null,
            'session' => $session !== null
                ? str_pad(
                    $session,
                    $this->suite->sessionLength ?? throw new RuntimeException('Missing parsed OCRA session length.'),
                    "\0",
                    STR_PAD_LEFT,
                )
                : null,
            'timestamp' => $timestamp,
        ];
    }

    private function validOutputShape(string $otp): bool
    {
        if ($this->suite->digits > 0) {
            return strlen($otp) === $this->suite->digits && ctype_digit($otp);
        }

        $length = match ($this->suite->algorithm) {
            'sha1' => 40,
            'sha256' => 64,
            'sha512' => 128,
            default => throw new RuntimeException('Invalid parsed OCRA algorithm.'),
        };

        return strlen($otp) === $length && ctype_xdigit($otp);
    }

    private function verifyChallenge(
        string $otp,
        string $challenge,
        ?int $counter,
        ?string $pin,
        ?string $session,
        ?int $timestamp,
        ?VerificationWindow $timeWindow,
        ?AuthenticationStateCacheInterface $cache = null,
        ?string $factorId = null,
        ?int $replayTtl = null,
        bool $composite = false,
    ): VerificationResult {
        $window = $timeWindow ?? new VerificationWindow();
        $operation = $this->prepareOperation($challenge, $counter, $pin, $session, $timestamp, $composite);
        $this->assertVerificationWindow($window, $cache, $factorId, $replayTtl);
        if (!$this->validOutputShape($otp)) {
            return VerificationResult::malformed();
        }

        $match = $this->findTimeMatch(strtoupper($otp), $challenge, $operation, $window);
        if ($match === null) {
            return VerificationResult::mismatch();
        }
        if (
            $cache !== null
            && $factorId !== null
            && $this->isReplay($cache, $factorId, $counter ?? 0, $match['message'], $replayTtl)
        ) {
            return VerificationResult::replay(matchedCounter: $counter, driftOffset: $match['offset']);
        }

        if ($match['offset'] !== 0) {
            return VerificationResult::success(
                VerificationReason::Drifted,
                matchedTimestep: intdiv(
                    $timestamp ?? throw new RuntimeException('Missing OCRA timestamp.'),
                    $this->suite->timeStepSeconds ?? throw new RuntimeException('Missing OCRA time step.'),
                ) + $match['offset'],
                driftOffset: $match['offset'],
            );
        }

        return VerificationResult::success(
            VerificationReason::Matched,
            matchedCounter: $counter,
            nextCounter: $counter !== null && $counter < PHP_INT_MAX ? $counter + 1 : null,
        );
    }
}
