<?php

declare(strict_types=1);

test('No debugging statements', function () {
    expect(['dd', 'dump', 'ray', 'die', 'd', 'eval', 'sleep', 'print_r', 'var_dump'])->each->not()->toBeUsed();
});

test('No echo statements', function () {
    expect(['echo', 'print'])->each->not()->toBeUsed();
});

test('No insecure randomness, serialization, or legacy digests', function () {
    expect(['rand', 'mt_rand', 'uniqid', 'serialize', 'unserialize', 'md5'])->each->not()->toBeUsed();
});
