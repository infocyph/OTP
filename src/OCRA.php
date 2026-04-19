<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use DateTimeInterface;
use Exception;
use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Exceptions\OCRAException;
use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\Support\AlgorithmValidator;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SecretUtility;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\OcraSuite;
use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;
use Infocyph\OTP\ValueObjects\SecretRotation;

final class OCRA
{
    private const string OCRA_REGEX = '/^OCRA-1:HOTP-SHA(1|256|512)-(0|[4-9]|10):(C-)?Q([ANH])(0[4-9]|[1-5]\d|6[0-4])(-(P(SHA1|SHA256|SHA512)|S\d{3}|(T((\d|[1-3]\d|4[0-8])H|(([1-9]|[1-5]\d)([SM]))))))*$/';

    /**
     * @var array{suite:string,algo:string,length:int,c:bool,q:array{format:string,value:int},optionals:array<int,array{format:string,value:int|string}>}
     */
    private array $ocraSuite;

    private ?string $pin = null;

    private ?string $session = null;

    private ?string $time = null;

    public function __construct(string $ocraSuite, private readonly string $sharedKey)
    {
        $this->validateAndParse($ocraSuite);
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
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
            $this->sharedKey,
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
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
     */
    public function getProvisioningUri(
        string $label,
        string $issuer,
        array $include = ['algorithm', 'digits'],
        array $additionalParameters = [],
    ): string {
        return ProvisioningUriBuilder::build(
            'ocra',
            $this->sharedKey,
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
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
        if ($gracePeriodInSeconds !== null && $gracePeriodInSeconds < 0) {
            throw new OCRAException('Grace period must be non-negative.');
        }

        $next = new self($this->ocraSuite['suite'], $newSecret);

        return new SecretRotation(
            $this->sharedKey,
            $newSecret,
            $gracePeriodInSeconds !== null ? new \DateTimeImmutable()->setTimestamp(($now ?? time()) + $gracePeriodInSeconds) : null,
            $next->getEnrollmentPayload($label, $issuer, $include, $additionalParameters, $withQrSvg, $imageSize),
        );
    }

    public function setPin(string $pin): self
    {
        if ($pin === '') {
            throw new OCRAException('PIN cannot be empty.');
        }
        $this->pin = $pin;

        return $this;
    }

    public function setSession(string $session): self
    {
        if ($session === '') {
            throw new OCRAException('Session cannot be empty.');
        }
        $this->session = $session;

        return $this;
    }

    public function setTime(DateTimeInterface $dateTime): self
    {
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
        $expected = $this->generate($challenge, $counter);
        if (!hash_equals($expected, $otp)) {
            return new VerificationResult(false, 'mismatch');
        }

        if ($replayStore !== null && $binding !== null) {
            $token = $challenge . '|' . $counter;
            if ($replayStore->hasConsumed('ocra:challenge', $binding, $token)) {
                return new VerificationResult(false, 'replay', matchedCounter: $counter, replayDetected: true);
            }

            $replayStore->markConsumed('ocra:challenge', $binding, $token);
            if ($this->ocraSuite['c']) {
                $replayStore->setState('ocra:last_counter', $binding, $counter);
            }
        }

        return new VerificationResult(true, 'matched', matchedCounter: $counter, verifiedAt: new \DateTimeImmutable());
    }

    private function assertChallenge(string $challenge): void
    {
        $length = $this->ocraSuite['q']['value'];
        match ($this->ocraSuite['q']['format']) {
            'n' => preg_match('/^\d{' . $length . '}$/', $challenge) === 1 || throw new OCRAException('Challenge must be a numeric string of the expected length.'),
            'a' => preg_match('/^[A-Za-z0-9]{1,128}$/', $challenge) === 1 || throw new OCRAException('Challenge must be alphanumeric and at most 128 characters.'),
            'h' => preg_match('/^[A-Fa-f0-9]{1,' . ($length * 2) . '}$/', $challenge) === 1 || throw new OCRAException('Challenge must be hexadecimal.'),
            default => throw new OCRAException('Invalid challenge format'),
        };
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
            'n' => str_pad(pack('H*', dechex((int) $input)), 128, "\0"),
            'a' => str_pad(substr($input, 0, 128), 128, "\0"),
            'h' => str_pad(pack('H*', substr($input, 0, 256)), 128, "\0"),
            default => throw new OCRAException('Unsupported challenge format.'),
        };
    }

    /**
     * @param array<int, string> $parts
     * @return array{c:bool,q:array{format:string,value:int},optionals:array<int, array{format:string,value:int|string}>}
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
        if (!preg_match(self::OCRA_REGEX, $ocraSuite, $matches) || $matches[0] !== $ocraSuite) {
            throw new OCRAException('Invalid OCRA Suite.');
        }

        $parts = explode(':', str_replace('-', ':', strtolower($ocraSuite)));
        $conditionalParts = $this->prepareConditionalParts($parts);
        $this->ocraSuite = [
            'suite' => $ocraSuite,
            'algo' => AlgorithmValidator::normalize($parts[3]),
            'length' => (int) $parts[4],
        ] + $conditionalParts;
    }
}
