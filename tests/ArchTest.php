<?php

test('No debugging statements', function () {
    expect(['dd', 'dump', 'ray', 'die', 'd', 'eval', 'sleep', 'print_r', 'var_dump'])->each->not()->toBeUsed();
});

test('No echo statements', function () {
    expect(['echo', 'print'])->each->not()->toBeUsed();
});
