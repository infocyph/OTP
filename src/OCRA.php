<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use DateTimeInterface;
use Exception;
use Infocyph\OTP\Contracts\AtomicReplayStoreInterface;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Exceptions\OCRAException;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\OcraSuiteValidator;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\ReplayProtection;
use Infocyph\OTP\Support\SecretRotationPlanner;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\OcraSuite;
use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;
use Infocyph\OTP\ValueObjects\SecretRotation;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32;

final class OCRA
{
    private readonly string $base32Secret;

    /**
     * @var array{suite:string,algo:string,length:int,c:bool,q:array{format:string,value:int},optionals:array<int,array{format:string,value:int|string}>}
     */
    private array $ocraSuite;

    private ?string $pin = null;

    private ?string $session = null;

    private ?string $time = null;

    public function __construct(string $ocraSuite, private readonly string $sharedKey)
    {
        if (strlen($sharedKey) < 16 || strlen($sharedKey) > 1024) {
            throw new OCRAException('OCRA shared keys must contain between 16 and 1024 bytes.');
        }

        $this->base32Secret = rtrim(Base32::encodeUpper($sharedKey), '=');
        $this->validateAndParse($ocraSuite);
    }

    public static function fromBase32(string $ocraSuite, string $secret): self
    {
        return new self($ocraSuite, SecretUtility::decodeBase32($secret));
    }

    /**
     * @param $bytes Secret byte length.
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
     * @param $challenge Challenge value.
     * @param $counter Counter value when suite requires `C`.
     * @throws Exception
     */
    public function generate(string $challenge, int $counter = 0): string
    {
        $this->assertChallenge($challenge);
        if ($counter < 0) {
            throw new OCRAException('Counter must be non-negative.');
        }

        $msg = $this->ocraSuite['suite'] . "\0";
        if ($this->ocraSuite['c']) {
            $msg .= pack('NN', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
        }
        $msg .= $this->calculateQ($challenge);
        if ($this->ocraSuite['optionals'] !== []) {
            $msg .= $this->calculateOptionals();
        }

        $hash = hash_hmac($this->ocraSuite['algo'], $msg, $this->sharedKey, true);
        if ($this->ocraSuite['length'] === 0) {
            return $hash;
        }

        $unpacked = unpack('Nvalue', substr($hash, ord(substr($hash, -1)) & 0x0F, 4));
        if ($unpacked === false) {
            throw new OCRAException('Unable to unpack OCRA hash fragment.');
        }
        $value = $unpacked['value'];
        if (!is_int($value)) {
            throw new OCRAException('Invalid OCRA hash fragment value.');
        }

        return str_pad(
            (string) (($value & 0x7FFFFFFF) % (10 ** $this->ocraSuite['length'])),
            $this->ocraSuite['length'],
            '0',
            STR_PAD_LEFT,
        );
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
        array $include = ['algorithm', 'digits'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): EnrollmentPayload {
        $uri = $this->getProvisioningUri($label, $issuer, $include, $additionalParameters);

        return ProvisioningUriBuilder::enrollmentPayload(
            'ocra',
            $this->base32Secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            AlgorithmValidator::normalize($this->ocraSuite['algo']),
            $this->ocraSuite['length'],
            null,
            null,
            $this->ocraSuite['suite'],
            $withQrSvg ? SvgQrRenderer::render($uri, $imageSize) : null,
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
        array $include = ['algorithm', 'digits'],
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'ocra',
            $this->base32Secret,
            $label,
            $issuer,
            array_fill_keys($include, true),
            $additionalParameters,
            AlgorithmValidator::normalize($this->ocraSuite['algo']),
            $this->ocraSuite['length'],
            null,
            null,
            $this->ocraSuite['suite'],
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
        array $include = ['algorithm', 'digits'],
        array $additionalParameters = [],
        int $imageSize = 200,
    ): string {
        return SvgQrRenderer::render(
            $this->getProvisioningUri($label, $issuer, $include, $additionalParameters),
            $imageSize,
        );
    }

    public function getSuite(): OcraSuite
    {
        return new OcraSuite(
            $this->ocraSuite['suite'],
            $this->ocraSuite['algo'],
            $this->ocraSuite['length'],
            $this->ocraSuite['c'],
            $this->ocraSuite['q']['format'],
            $this->ocraSuite['q']['value'],
            $this->ocraSuite['optionals'],
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
        array $include = ['algorithm', 'digits'],
        array $additionalParameters = [],
        bool $withQrSvg = false,
        int $imageSize = 200,
    ): SecretRotation {
        try {
            $rotation = SecretRotationPlanner::prepare(
                $this->base32Secret,
                $newSecret,
                $gracePeriodInSeconds,
                $now,
            );
        } catch (InvalidArgumentException $exception) {
            throw new OCRAException($exception->getMessage(), previous: $exception);
        }

        $next = self::fromBase32($this->ocraSuite['suite'], $rotation['nextSecret']);

        return new SecretRotation(
            $this->base32Secret,
            $rotation['nextSecret'],
            $rotation['overlapUntil'] !== null ? new \DateTimeImmutable()->setTimestamp($rotation['overlapUntil']) : null,
            $next->getEnrollmentPayload($label, $issuer, $include, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    public function setPin(string $pin): self
    {
        if ($pin === '' || strlen($pin) > 1024) {
            throw new OCRAException('PIN must contain between 1 and 1024 bytes.');
        }
        $this->pin = $pin;

        return $this;
    }

    public function setSession(string $session): self
    {
        if ($session === '' || strlen($session) % 2 !== 0 || !ctype_xdigit($session)) {
            throw new OCRAException('Session must be a non-empty, even-length hexadecimal string.');
        }
        foreach ($this->ocraSuite['optionals'] as $optional) {
            if ($optional['format'] === 's' && strlen($session) > ((int) $optional['value'] * 2)) {
                throw new OCRAException('Session exceeds the byte length configured by the OCRA suite.');
            }
        }
        $this->session = $session;

        return $this;
    }

    public function setTime(DateTimeInterface $dateTime): self
    {
        if ($dateTime->getTimestamp() < 0) {
            throw new OCRAException('OCRA timestamps must be non-negative.');
        }
        $this->time = $dateTime->format('U');

        return $this;
    }

    public function verify(string $otp, string $challenge, int $counter = 0): bool
    {
        return $this->verifyWithResult($otp, $challenge, $counter)->matched;
    }

    public function verifyWithResult(
        string $otp,
        string $challenge,
        int $counter = 0,
        ?ReplayStoreInterface $replayStore = null,
        ?string $binding = null,
    ): VerificationResult {
        if (
            $this->ocraSuite['length'] > 0
            && (strlen($otp) !== $this->ocraSuite['length'] || !ctype_digit($otp))
        ) {
            return new VerificationResult(false, 'malformed');
        }
        $this->assertReplayBinding($replayStore, $binding);
        $expected = $this->generate($challenge, $counter);
        if (!hash_equals($expected, $otp)) {
            return new VerificationResult(false, 'mismatch');
        }

        if (
            $replayStore !== null
            && $binding !== null
            && $this->isReplay($replayStore, $binding, $challenge, $counter)
        ) {
            return new VerificationResult(false, 'replay', matchedCounter: $counter, replayDetected: true);
        }

        return new VerificationResult(true, 'matched', matchedCounter: $counter, verifiedAt: new \DateTimeImmutable());
    }

    private static function decimalToBinary(string $decimal): string
    {
        $decimal = ltrim($decimal, '0');
        if ($decimal === '') {
            return "\0";
        }

        $binary = '';
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

            $binary = dechex($remainder) . $binary;
            $decimal = $quotient;
        }

        return pack('H*', $binary);
    }

    private function assertChallenge(string $challenge): void
    {
        $length = $this->ocraSuite['q']['value'];
        match ($this->ocraSuite['q']['format']) {
            'n' => preg_match('/^\d{1,' . $length . '}$/', $challenge) === 1 || throw new OCRAException('Challenge must be a numeric string within the configured length.'),
            'a' => preg_match('/^[A-Za-z0-9]{1,128}$/', $challenge) === 1 || throw new OCRAException('Challenge must be alphanumeric and at most 128 characters.'),
            'h' => preg_match('/^[A-Fa-f0-9]{1,' . $length . '}$/', $challenge) === 1 || throw new OCRAException('Challenge must be hexadecimal.'),
            default => throw new OCRAException('Invalid challenge format'),
        };
    }

    private function assertReplayBinding(?ReplayStoreInterface $replayStore, ?string $binding): void
    {
        if (($replayStore === null) !== ($binding === null)) {
            throw new OCRAException('Replay store and binding must be provided together.');
        }
        if ($binding !== null && (trim($binding) === '' || strlen($binding) > 512)) {
            throw new OCRAException('Replay binding must contain between 1 and 512 bytes.');
        }
    }

    private function calculateOptionals(): string
    {
        $optionals = '';
        foreach ($this->ocraSuite['optionals'] as $optional) {
            $optionals .= match ($optional['format']) {
                'p' => hash((string) $optional['value'], $this->pin ?? throw new OCRAException('Missing PIN'), true),
                's' => str_pad(pack('H*', $this->session ?? throw new OCRAException('Missing Session')), (int) $optional['value'], "\0", STR_PAD_LEFT),
                't' => [
                    $time = (int) floor(((int) ($this->time ?? (string) time())) / (int) $optional['value']),
                    pack('NN', ($time >> 32) & 0xFFFFFFFF, $time & 0xFFFFFFFF),
                ][1],
                default => throw new OCRAException('Invalid optional part format'),
            };
        }

        return $optionals;
    }

    private function calculateQ(string $input): string
    {
        return match ($this->ocraSuite['q']['format']) {
            'n' => str_pad(self::decimalToBinary($input), 128, "\0"),
            'a' => str_pad(substr($input, 0, 128), 128, "\0"),
            'h' => str_pad(pack('H*', substr($input, 0, 256)), 128, "\0"),
            default => throw new OCRAException('Unsupported challenge format.'),
        };
    }

    private function isCounterReplay(
        ReplayStoreInterface $replayStore,
        string $binding,
        int $counter,
    ): bool {
        return !ReplayProtection::advance($replayStore, 'ocra:last_counter', $binding, $counter);
    }

    private function isReplay(
        ReplayStoreInterface $replayStore,
        string $binding,
        string $challenge,
        int $counter,
    ): bool {
        if ($this->ocraSuite['c']) {
            return $this->isCounterReplay($replayStore, $binding, $counter);
        }

        $token = $challenge . '|' . $counter;
        if ($replayStore instanceof AtomicReplayStoreInterface) {
            $consumed = $replayStore->consumeOnce('ocra:challenge', $binding, $token);
        } else {
            $consumed = !$replayStore->hasConsumed('ocra:challenge', $binding, $token);
            if ($consumed) {
                $replayStore->markConsumed('ocra:challenge', $binding, $token);
            }
        }

        if (!$consumed) {
            return true;
        }

        return false;
    }

    /**
     * @param $parts Parsed OCRA suite parts.
     * @return array Parsed conditional suite data.
     * @phpstan-param array<int, string> $parts
     * @phpstan-return array{c:bool,q:array{format:string,value:int},optionals:array<int, array{format:string,value:int|string}>}
     */
    private function prepareConditionalParts(array $parts): array
    {
        $conditionalParts = $parts[5] === 'c'
            ? ['c' => true, 'q' => substr($parts[6], 1), 'optionals' => array_slice($parts, 7)]
            : ['c' => false, 'q' => substr($parts[5], 1), 'optionals' => array_slice($parts, 6)];

        $conditionalParts['q'] = [
            'format' => $conditionalParts['q'][0],
            'value' => (int) substr($conditionalParts['q'], 1),
        ];

        $conditionalParts['optionals'] = array_map(function (string $optional): array {
            $value = substr($optional, 1);

            return [
                'format' => $optional[0],
                'value' => match ($optional[0]) {
                    's' => (int) $value,
                    'p' => strtoupper($value),
                    't' => match (substr($value, -1)) {
                        's' => (int) rtrim($value, 's'),
                        'm' => (int) rtrim($value, 'm') * 60,
                        'h' => (int) rtrim($value, 'h') * 3600,
                        default => throw new OCRAException('Invalid time format'),
                    },
                    default => throw new OCRAException('Invalid optional format'),
                },
            ];
        }, $conditionalParts['optionals']);

        return $conditionalParts;
    }

    private function validateAndParse(string $ocraSuite): void
    {
        if (!OcraSuiteValidator::isValid($ocraSuite)) {
            throw new OCRAException('Invalid OCRA Suite.');
        }

        $parts = explode(':', str_replace('-', ':', strtolower($ocraSuite)));
        $conditionalParts = $this->prepareConditionalParts($parts);
        $this->ocraSuite = [
            'suite' => $ocraSuite,
            'algo' => AlgorithmValidator::normalize($parts[3]),
            'length' => (int) $parts[4],
        ] + $conditionalParts;

        foreach ($this->ocraSuite['optionals'] as $optional) {
            if ($optional['format'] === 's' && ((int) $optional['value'] < 1 || (int) $optional['value'] > 512)) {
                throw new OCRAException('OCRA session length must be between 1 and 512 bytes.');
            }
        }
    }
}
