<?php

declare(strict_types=1);

/**
 * Lightweight recursive PHP syntax check using `php -l`.
 *
 * Usage:
 *   php .github/scripts/syntax.php [path ...]
 */

$paths = array_slice($_SERVER['argv'] ?? [], 1);
if ($paths === []) {
    fwrite(STDERR, "Error: at least one path is required.\n");
    fwrite(STDERR, "Usage: php .github/scripts/syntax.php [path ...]\n");
    exit(2);
}

$files = [];

foreach ($paths as $path) {
    if (! is_string($path) || $path === '') {
        continue;
    }

    if (is_file($path)) {
        if (str_ends_with($path, '.php')) {
            $files[] = $path;
        }

        continue;
    }

    if (! is_dir($path)) {
        continue;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $entry) {
        if (! $entry instanceof SplFileInfo) {
            continue;
        }

        if (! $entry->isFile()) {
            continue;
        }

        $filename = $entry->getFilename();
        if (! str_ends_with($filename, '.php')) {
            continue;
        }

        $files[] = $entry->getPathname();
    }
}

$files = array_values(array_unique($files));
sort($files);

if ($files === []) {
    fwrite(STDOUT, "No PHP files found.\n");
    exit(0);
}

$failed = [];

foreach ($files as $file) {
    $command = [PHP_BINARY, '-d', 'display_errors=1', '-l', $file];
    $descriptorSpec = [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open($command, $descriptorSpec, $pipes);

    if (! is_resource($process)) {
        $failed[] = [$file, 'Could not start PHP lint process'];
        continue;
    }

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);

    if ($exitCode !== 0) {
        $output = trim((string) $stdout . "\n" . (string) $stderr);
        $failed[] = [$file, $output !== '' ? $output : 'Unknown lint failure'];
    }
}

if ($failed === []) {
    fwrite(STDOUT, sprintf("Syntax OK: %d PHP files checked.\n", count($files)));
    exit(0);
}

fwrite(STDERR, sprintf("Syntax errors in %d file(s):\n", count($failed)));

foreach ($failed as [$file, $error]) {
    fwrite(STDERR, "- {$file}\n{$error}\n");
}

exit(1);
