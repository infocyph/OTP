<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\CacheLayer\Cache\AuthenticationStateCacheInterface;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\CacheLock;
use Infocyph\OTP\ValueObjects\VerificationWindow;
use InvalidArgumentException;

final readonly class MobileOTP
{
    public const int OUTPUT_LENGTH = 6;

    public const int PERIOD = 10;

    private const int MAX_FACTOR_ID_LENGTH = 190;

    private const int MAX_OFFSET_STEPS = 8640;

    private const int MAX_WINDOW_STEPS = 18;

    private string $pin;

    private string $secret;

    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        string $pin,
    ) {
        self::assertSecret($secret);
        self::assertPin($pin);
        $this->pin = $pin;
        $this->secret = $secret;
    }

    public static function generateSecret(): string
    {
        return bin2hex(random_bytes(8));
    }

    public function generate(?int $timestamp = null, int $offsetSteps = 0): string
    {
        $step = $this->getTimeStepFromTimestamp($timestamp ?? time(), $offsetSteps);

        return substr(hash('md5', $step . $this->secret . $this->pin), 0, self::OUTPUT_LENGTH);
    }

    public function getTimeStepFromTimestamp(int $timestamp, int $offsetSteps = 0): int
    {
        self::assertOffset($offsetSteps);
        if ($timestamp < 0) {
            throw new InvalidArgumentException('MobileOTP timestamp must be non-negative.');
        }

        $step = intdiv($timestamp, self::PERIOD);
        if (($offsetSteps > 0 && $step > PHP_INT_MAX - $offsetSteps) || $step + $offsetSteps < 0) {
            throw new InvalidArgumentException('MobileOTP timestamp and offset exceed the supported range.');
        }

        return $step + $offsetSteps;
    }

    public function verify(
        #[\SensitiveParameter]
        string $otp,
        ?int $timestamp = null,
        int $pastWindows = 0,
        int $futureWindows = 0,
        int $offsetSteps = 0,
    ): bool {
        return $this->verifyWithWindow(
            $otp,
            $timestamp,
            new VerificationWindow($pastWindows, $futureWindows),
            $offsetSteps,
        )->matched;
    }

    public function verifyWithWindow(
        #[\SensitiveParameter]
        string $otp,
        ?int $timestamp = null,
        ?VerificationWindow $window = null,
        int $offsetSteps = 0,
        ?AuthenticationStateCacheInterface $cache = null,
        ?string $factorId = null,
    ): VerificationResult {
        $window ??= new VerificationWindow();
        self::assertReplayConfiguration($cache, $factorId);
        self::assertWindow($window);
        $currentStep = $this->getTimeStepFromTimestamp($timestamp ?? time(), $offsetSteps);
        if (strlen($otp) !== self::OUTPUT_LENGTH || preg_match('/\A[0-9a-f]{6}\z/D', $otp) !== 1) {
            return VerificationResult::malformed();
        }

        $match = $this->findMatch($otp, $currentStep, $window);
        if ($match === null) {
            return VerificationResult::mismatch();
        }
        if ($cache !== null && $factorId !== null) {
            $ttl = self::PERIOD * ($window->past + $window->future + 1);
            if (!$this->advanceReplayState($cache, $factorId, $match['step'], $ttl)) {
                return VerificationResult::replay($match['step'], driftOffset: $match['offset']);
            }
        }

        return VerificationResult::success(
            $match['offset'] === 0 ? VerificationReason::Matched : VerificationReason::Drifted,
            matchedTimestep: $match['step'],
            driftOffset: $match['offset'],
        );
    }

    private static function assertFactorId(string $factorId): void
    {
        if ($factorId === '' || strlen($factorId) > self::MAX_FACTOR_ID_LENGTH) {
            throw new InvalidArgumentException('Factor IDs must contain between 1 and 190 bytes.');
        }
    }

    private static function assertOffset(int $offsetSteps): void
    {
        if ($offsetSteps < -self::MAX_OFFSET_STEPS || $offsetSteps > self::MAX_OFFSET_STEPS) {
            throw new InvalidArgumentException('MobileOTP offset may not exceed 24 hours in either direction.');
        }
    }

    private static function assertPin(string $pin): void
    {
        if (strlen($pin) !== 4 || !ctype_digit($pin)) {
            throw new InvalidArgumentException('MobileOTP PIN must contain exactly 4 decimal digits.');
        }
    }

    private static function assertReplayConfiguration(
        ?AuthenticationStateCacheInterface $cache,
        ?string $factorId,
    ): void {
        if (($cache === null) !== ($factorId === null)) {
            throw new InvalidArgumentException('CacheLayer authentication state cache and factor ID must be provided together.');
        }
        if ($factorId !== null) {
            self::assertFactorId($factorId);
        }
        if ($cache !== null) {
            CacheLock::assertSafe($cache);
        }
    }

    private static function assertSecret(string $secret): void
    {
        if (strlen($secret) !== 16 || preg_match('/\A[0-9A-Fa-f]{16}\z/D', $secret) !== 1) {
            throw new InvalidArgumentException('MobileOTP secret must contain exactly 16 hexadecimal characters.');
        }
    }

    private static function assertWindow(VerificationWindow $window): void
    {
        if ($window->past > self::MAX_WINDOW_STEPS || $window->future > self::MAX_WINDOW_STEPS) {
            throw new InvalidArgumentException('MobileOTP verification windows may not exceed 18 ten-second steps per direction.');
        }
    }

    private function advanceReplayState(
        AuthenticationStateCacheInterface $cache,
        string $factorId,
        int $timeStep,
        int $ttl,
    ): bool {
        $stateKey = hash('sha256', "infocyph:otp:mobile:timestep:v1\0" . $factorId);
        $lockKey = hash('sha256', "infocyph:otp:mobile:lock:v1\0" . $factorId);

        return CacheLock::advance($cache, $stateKey, $lockKey, $timeStep, $ttl, 'MobileOTP replay');
    }

    /** @return array{step:int,offset:int}|null */
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
        $candidate = substr(hash('md5', $step . $this->secret . $this->pin), 0, self::OUTPUT_LENGTH);

        return hash_equals($candidate, $otp);
    }
}
