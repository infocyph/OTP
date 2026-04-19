<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\ValueObject\PhpVersion;

return RectorConfig::configure()
    ->withPaths([__DIR__ . '/src'])
    ->withPreparedSets(deadCode: true)
    ->withPhpVersion(
        constant(PhpVersion::class . '::PHP_' . PHP_MAJOR_VERSION . PHP_MINOR_VERSION),
    )
    ->withPhpSets();
