<?php

declare(strict_types=1);

namespace Infocyph\OTP;

use Infocyph\OTP\Contracts\ReplayStoreInterface;
use Infocyph\OTP\Support\ProvisioningUriBuilder;
use Infocyph\OTP\Support\ProvisioningUriParser;
use Infocyph\OTP\Support\SvgQrRenderer;
use Infocyph\OTP\ValueObjects\EnrollmentPayload;
use Infocyph\OTP\ValueObjects\ParsedOtpAuthUri;

abstract class AbstractOtpAuthenticator
{
    public static function parseProvisioningUri(string $uri): ParsedOtpAuthUri
    {
        return ProvisioningUriParser::parse($uri);
    }

    final protected function assertOtp(string $otp, int $digitCount): void
    {
        if (!$this->isValidOtp($otp, $digitCount)) {
            throw new \InvalidArgumentException('OTP must be a numeric string matching the configured digit count.');
        }
    }

    final protected function assertReplayBinding(
        ?ReplayStoreInterface $replayStore,
        ?string $binding,
    ): void {
        if (($replayStore === null) !== ($binding === null)) {
            throw new \InvalidArgumentException('Replay store and binding must be provided together.');
        }
        if ($binding !== null && (trim($binding) === '' || strlen($binding) > 512)) {
            throw new \InvalidArgumentException('Replay binding must contain between 1 and 512 bytes.');
        }
    }

    /**
     * @param $otpType OTP type (`totp`, `hotp`, or `ocra`).
     * @param $secret Normalized Base32 secret.
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $algorithm HMAC algorithm name.
     * @param $digitCount OTP digit length.
     * @param $period TOTP period in seconds.
     * @param $counter HOTP counter value.
     * @param $withQrSvg Whether to render QR SVG.
     * @param $imageSize QR image size.
     * @param $uri Provisioning URI.
     *
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    final protected function buildEnrollmentPayload(
        string $otpType,
        string $secret,
        string $label,
        string $issuer,
        array $include,
        array $additionalParameters,
        string $algorithm,
        int $digitCount,
        ?int $period,
        ?int $counter,
        bool $withQrSvg,
        int $imageSize,
        string $uri,
    ): EnrollmentPayload {
        return ProvisioningUriBuilder::enrollmentPayload(
            $otpType,
            $secret,
            $label,
            $issuer,
            $this->includeFlags($include),
            $additionalParameters,
            $algorithm,
            $digitCount,
            $period,
            $counter,
            null,
            $withQrSvg ? SvgQrRenderer::render($uri, $imageSize) : null,
        );
    }

    /**
     * @param $otpType OTP type (`totp`, `hotp`, or `ocra`).
     * @param $secret Normalized Base32 secret.
     * @param $label Account label.
     * @param $issuer Issuer name.
     * @param $include Optional provisioning flags.
     * @param $additionalParameters Additional query parameters.
     * @param $algorithm HMAC algorithm name.
     * @param $digitCount OTP digit length.
     * @param $period TOTP period in seconds.
     * @param $counter HOTP counter value.
     *
     * @phpstan-param list<string> $include
     * @phpstan-param array<string, scalar|null> $additionalParameters
     */
    final protected function buildProvisioningUri(
        string $otpType,
        string $secret,
        string $label,
        string $issuer,
        array $include,
        array $additionalParameters,
        string $algorithm,
        int $digitCount,
        ?int $period,
        ?int $counter,
    ): string {
        return ProvisioningUriBuilder::build(
            $otpType,
            $secret,
            $label,
            $issuer,
            $this->includeFlags($include),
            $additionalParameters,
            $algorithm,
            $digitCount,
            $period,
            $counter,
        );
    }

    /**
     * @param array $include Optional provisioning flags.
     * @return array Include flags keyed by name.
     * @phpstan-param list<string> $include
     * @phpstan-return array<string, bool>
     */
    final protected function includeFlags(array $include): array
    {
        return array_fill_keys($include, true);
    }

    final protected function isValidOtp(string $otp, int $digitCount): bool
    {
        return strlen($otp) === $digitCount && ctype_digit($otp);
    }
}
