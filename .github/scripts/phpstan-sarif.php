<?php

declare(strict_types=1);

/**
 * Convert PHPStan JSON output to SARIF 2.1.0 for GitHub Code Scanning upload.
 *
 * Usage:
 *   php .github/scripts/phpstan-sarif.php <phpstan-json> [sarif-output]
 */

$argv = $_SERVER['argv'] ?? [];
$input = $argv[1] ?? '';
$output = $argv[2] ?? 'phpstan-results.sarif';

if (! is_string($input) || $input === '') {
    fwrite(STDERR, "Error: missing input file.\n");
    fwrite(STDERR, "Usage: php .github/scripts/phpstan-sarif.php <phpstan-json> [sarif-output]\n");
    exit(2);
}

if (! is_file($input) || ! is_readable($input)) {
    fwrite(STDERR, "Error: input file not found or unreadable: {$input}\n");
    exit(2);
}

$raw = file_get_contents($input);
if ($raw === false) {
    fwrite(STDERR, "Error: failed to read input file: {$input}\n");
    exit(2);
}

$decoded = json_decode($raw, true);
if (! is_array($decoded)) {
    fwrite(STDERR, "Error: input is not valid JSON.\n");
    exit(2);
}

/**
 * @return non-empty-string
 */
function normalizeUri(string $path): string
{
    $normalized = str_replace('\\', '/', $path);
    $cwd = getcwd();

    if (is_string($cwd) && $cwd !== '') {
        $cwd = rtrim(str_replace('\\', '/', $cwd), '/');

        if (preg_match('/^[A-Za-z]:\//', $normalized) === 1) {
            if (stripos($normalized, $cwd . '/') === 0) {
                $normalized = substr($normalized, strlen($cwd) + 1);
            }
        } elseif (str_starts_with($normalized, '/')) {
            if (str_starts_with($normalized, $cwd . '/')) {
                $normalized = substr($normalized, strlen($cwd) + 1);
            }
        }
    }

    $normalized = ltrim($normalized, './');

    return $normalized === '' ? 'unknown.php' : $normalized;
}

$results = [];
$rules = [];

$globalErrors = $decoded['errors'] ?? [];
if (is_array($globalErrors)) {
    foreach ($globalErrors as $error) {
        if (! is_string($error) || $error === '') {
            continue;
        }

        $ruleId = 'phpstan.internal';
        $rules[$ruleId] = true;
        $results[] = [
            'ruleId' => $ruleId,
            'level' => 'error',
            'message' => [
                'text' => $error,
            ],
        ];
    }
}

$files = $decoded['files'] ?? [];
if (is_array($files)) {
    foreach ($files as $filePath => $fileData) {
        if (! is_string($filePath) || ! is_array($fileData)) {
            continue;
        }

        $messages = $fileData['messages'] ?? [];
        if (! is_array($messages)) {
            continue;
        }

        foreach ($messages as $messageData) {
            if (! is_array($messageData)) {
                continue;
            }

            $messageText = (string) ($messageData['message'] ?? 'PHPStan issue');
            $line = (int) ($messageData['line'] ?? 1);
            $identifier = (string) ($messageData['identifier'] ?? '');
            $ruleId = $identifier !== '' ? $identifier : 'phpstan.issue';

            if ($line < 1) {
                $line = 1;
            }

            $rules[$ruleId] = true;
            $results[] = [
                'ruleId' => $ruleId,
                'level' => 'error',
                'message' => [
                    'text' => $messageText,
                ],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => normalizeUri($filePath),
                        ],
                        'region' => [
                            'startLine' => $line,
                        ],
                    ],
                ]],
            ];
        }
    }
}

$ruleDescriptors = [];
$ruleIds = array_keys($rules);
sort($ruleIds);

foreach ($ruleIds as $ruleId) {
    $ruleDescriptors[] = [
        'id' => $ruleId,
        'name' => $ruleId,
        'shortDescription' => [
            'text' => $ruleId,
        ],
    ];
}

$sarif = [
    '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
    'version' => '2.1.0',
    'runs' => [[
        'tool' => [
            'driver' => [
                'name' => 'PHPStan',
                'informationUri' => 'https://phpstan.org/',
                'rules' => $ruleDescriptors,
            ],
        ],
        'results' => $results,
    ]],
];

$encoded = json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (! is_string($encoded)) {
    fwrite(STDERR, "Error: failed to encode SARIF JSON.\n");
    exit(2);
}

$written = file_put_contents($output, $encoded . PHP_EOL);
if ($written === false) {
    fwrite(STDERR, "Error: failed to write output file: {$output}\n");
    exit(2);
}

fwrite(STDOUT, sprintf("SARIF generated: %s (%d findings)\n", $output, count($results)));
exit(0);
