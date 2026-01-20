<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/src',
    ])
    ->withSets([
        constant("Rector\Set\ValueObject\LevelSetList::UP_TO_PHP_82"),
    ]);
