<?php

declare(strict_types=1);

$command = 'composer audit --format=json --no-interaction --abandoned=report';

$descriptorSpec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$process = proc_open($command, $descriptorSpec, $pipes);

if (! \is_resource($process)) {
    fwrite(STDERR, "Failed to start composer audit process.\n");
    exit(1);
}

fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]) ?: '';
$stderr = stream_get_contents($pipes[2]) ?: '';
fclose($pipes[1]);
fclose($pipes[2]);

$exitCode = proc_close($process);

/** @var array<string,mixed>|null $decoded */
$decoded = json_decode($stdout, true);

if (! \is_array($decoded)) {
    fwrite(STDERR, "Unable to parse composer audit JSON output.\n");
    if (trim($stdout) !== '') {
        fwrite(STDERR, $stdout . "\n");
    }
    if (trim($stderr) !== '') {
        fwrite(STDERR, $stderr . "\n");
    }

    exit($exitCode !== 0 ? $exitCode : 1);
}

$advisories = $decoded['advisories'] ?? [];
$abandoned = $decoded['abandoned'] ?? [];

$advisoryCount = 0;

if (\is_array($advisories)) {
    foreach ($advisories as $entries) {
        if (\is_array($entries)) {
            $advisoryCount += \count($entries);
        }
    }
}

$abandonedPackages = [];

if (\is_array($abandoned)) {
    foreach ($abandoned as $package => $replacement) {
        if (\is_string($package) && $package !== '') {
            $abandonedPackages[$package] = $replacement;
        }
    }
}

echo sprintf(
    "Composer audit summary: %d advisories, %d abandoned packages.\n",
    $advisoryCount,
    \count($abandonedPackages),
);

if ($abandonedPackages !== []) {
    fwrite(STDERR, "Warning: abandoned packages detected (non-blocking):\n");
    foreach ($abandonedPackages as $package => $replacement) {
        $target = \is_string($replacement) && $replacement !== '' ? $replacement : 'none';
        fwrite(STDERR, sprintf(" - %s (replacement: %s)\n", $package, $target));
    }
}

if ($advisoryCount > 0) {
    fwrite(STDERR, "Security vulnerabilities detected by composer audit.\n");
    exit(1);
}

exit(0);
