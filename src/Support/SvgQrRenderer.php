<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use InvalidArgumentException;

final class SvgQrRenderer
{
    public static function render(#[\SensitiveParameter] string $payload, int $imageSize = 200): string
    {
        if ($payload === '' || strlen($payload) > 4096) {
            throw new InvalidArgumentException('QR payload must contain between 1 and 4096 bytes.');
        }
        if ($imageSize < 64 || $imageSize > 4096) {
            throw new InvalidArgumentException('QR image size must be between 64 and 4096 pixels.');
        }

        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle($imageSize),
                new SvgImageBackEnd(),
            ),
        );

        return $writer->writeString($payload);
    }
}
