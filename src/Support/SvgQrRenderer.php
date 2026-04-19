<?php

declare(strict_types=1);

namespace Infocyph\OTP\Support;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

final class SvgQrRenderer
{
    public static function render(string $payload, int $imageSize = 200): string
    {
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle($imageSize),
                new SvgImageBackEnd(),
            ),
        );

        return $writer->writeString($payload);
    }
}
