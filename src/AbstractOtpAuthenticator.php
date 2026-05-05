<?php

declare(strict_types=1);

namespace Infocyph\OTP;

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
        if (!preg_match('/^\d+$/', $otp) || strlen($otp) !== $digitCount) {
            throw new \InvalidArgumentException('OTP must be a numeric string matching the configured digit count.');
        }
    }

    /**
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
     * @param array<string> $include
     * @param array<string, scalar|null> $additionalParameters
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
     * @param array<string> $include
     * @return array<string, bool>
     */
    final protected function includeFlags(array $include): array
    {
        return array_fill_keys($include, true);
    }
}
