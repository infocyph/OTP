<?php

namespace Infocyph\OTP;

use DateTimeInterface;
use Exception;
use Infocyph\OTP\Exceptions\OCRAException;

final class OCRA
{
    private string $ocraRegex = '/^OCRA-1:HOTP-SHA(1|256|512)-(0|[4-9]|10):(C-)?Q([ANH])(0[4-9]|[1-5]\d|6[0-4])(-(P(SHA1|SHA256|SHA512)|S\d{3}|(T((\d|[1-3]\d|4[0-8])H|(([1-9]|[1-5]\d)([SM]))))))?/';

    private array $ocraSuite;
    private string $pin;
    private string $session;
    private string $time;

    /**
     * Constructor for the class.
     *
     * @param string $ocraSuite The OCRA suite string.
     * @param string $sharedKey The shared key for the OCRA instance.
     * @throws OCRAException If the OCRA suite is invalid.
     */
    public function __construct(string $ocraSuite, private readonly string $sharedKey)
    {
        $this->validateAndParse($ocraSuite);
    }

    /**
     * Sets the pin for the OCRA instance.
     *
     * Required if the suite supports session.
     *
     * @param string $pin The pin to set.
     * @return OCRA
     */
    public function setPin(string $pin): OCRA
    {
        $this->pin = $pin;
        return $this;
    }

    /**
     * Sets the session for the OCRA instance.
     *
     * Required if the suite supports session.
     *
     * @param string $session The session to set.
     * @return OCRA
     */
    public function setSession(string $session): OCRA
    {
        $this->session = $session;
        return $this;
    }

    /**
     * Sets the time for the OCRA instance.
     *
     * Only applicable if the suite supports time format.
     *
     * @param DateTimeInterface $dateTime The DateTime object to set the time from.
     * @return OCRA
     */
    public function setTime(DateTimeInterface $dateTime): OCRA
    {
        $this->time = $dateTime->format('U');
        return $this;
    }

    /**
     * Generates the OCRA code based on the input and optional counter.
     *
     * @param string $challenge The challenge for generating the OCRA code.
     * @param int $counter The optional counter value (default is 0).
     * @return string The generated OCRA code.
     * @throws Exception
     */
    public function generate(string $challenge, int $counter = 0): string
    {
        $msg = $this->ocraSuite['suite'] . "\0";

        if ($this->ocraSuite['c']) {
            $msg .= pack('NN', ($counter >> 32) & 0xffffffff, $counter & 0xffffffff);
        }

        $msg .= $this->calculateQ($challenge);

        if ($this->ocraSuite['optional']) {
            $msg .= $this->calculateOptionals();
        }

        $hash = hash_hmac((string) $this->ocraSuite['algo'], $msg, $this->sharedKey, true);

        if (!$this->ocraSuite['length']) {
            return $hash;
        }

        [, $value] = unpack('N', substr($hash, ord(substr($hash, -1)) & 0xf, 4));

        return str_pad(
            ($value & 0x7fffffff) % 10 ** $this->ocraSuite['length'],
            $this->ocraSuite['length'],
            '0',
            STR_PAD_LEFT
        );
    }

    /**
     * Calculates the value of Q based on the input and the format specified in the OCRA suite.
     *
     * @param string $input The input value to calculate Q for.
     * @return string The calculated value of Q.
     */
    private function calculateQ(string $input): string
    {
        return match ($this->ocraSuite['q']['format']) {
            'n' => str_pad(pack('H*', dechex($input)), 128, "\0"),
            'a' => str_pad(substr($input, 0, 128), 128, "\0"),
            'h' => str_pad(pack('H*', substr($input, 0, 256)), 128, "\0")
        };
    }

    /**
     * Calculates the optional value based on the format specified in the OCRA suite.
     *
     * @return string The calculated optional value.
     * @throws OCRAException
     */
    private function calculateOptionals(): string
    {
        return match ($this->ocraSuite['optional']['format']) {
            'p' => hash(
                (string) $this->ocraSuite['optional']['value'],
                $this->pin ?? throw new OCRAException('Missing PIN'),
                true
            ),
            's' => str_pad(
                pack('H*', $this->session ?? throw new OCRAException('Missing Session')),
                $this->ocraSuite['optional']['value'],
                "\0",
                STR_PAD_LEFT
            ),
            't' => [
                $time = (int)floor(($this->time ?? time()) / $this->ocraSuite['optional']['value']),
                pack('NN', ($time >> 32) & 0xffffffff, $time & 0xffffffff)
            ][1]
        };
    }

    /**
     * Validate & parse OCRA String
     *
     * @param string $ocraSuite The OCRA Suite
     * @throws OCRAException
     */
    private function validateAndParse(string $ocraSuite): void
    {
        if (!preg_match($this->ocraRegex, $ocraSuite, $matches)) {
            throw new OCRAException('Invalid OCRA Suite!');
        }

        if ($matches[0] !== $ocraSuite) {
            throw new OCRAException('Invalid OCRA Suite (Optional fields are invalid/malformed!)');
        }

        $parts = explode(':', str_replace('-', ':', strtolower($ocraSuite)));
        $this->ocraSuite = [
                'suite' => $ocraSuite,
                'algo' => $parts[3],
                'length' => $parts[4]
            ] + $this->prepareConditionalParts($parts);
    }

    /**
     * Prepares the conditional parts of an OCRA suite based on the given array of parts.
     *
     * @param array $parts The array of parts to prepare the conditional parts from.
     * @return array The prepared conditional parts.
     */
    private function prepareConditionalParts(array $parts): array
    {
        $conditionalParts = (
            $parts[5] === 'c'
            ? ['c' => true, 'q' => substr((string) $parts[6], 1), 'optional' => $parts[7] ?? null]
            : ['c' => false, 'q' => substr((string) $parts[5], 1), 'optional' => $parts[6] ?? null]
        );

        $conditionalParts['q'] = [
            'format' => $conditionalParts['q'][0],
            'value' => (int)($conditionalParts['q'][1] . $conditionalParts['q'][2]),
        ];

        if (!$conditionalParts['optional']) {
            return $conditionalParts;
        }

        $conditionalParts['optional'] = [
            'format' => $conditionalParts['optional'][0],
            'value' => substr((string) $conditionalParts['optional'], 1)
        ];
        $conditionalParts['optional']['value'] = match ($conditionalParts['optional']['format']) {
            's' => (int)$conditionalParts['optional']['value'],
            'p' => $conditionalParts['optional']['value'],
            't' => match (substr($conditionalParts['optional']['value'], -1)) {
                's' => (int)rtrim($conditionalParts['optional']['value'], 's'),
                'm' => (int)rtrim($conditionalParts['optional']['value'], 'm') * 60,
                'h' => (int)rtrim($conditionalParts['optional']['value'], 'h') * 3600
            }
        };

        return $conditionalParts;
    }
}
