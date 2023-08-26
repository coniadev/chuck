<?php

// phpcs:ignoreFile

declare(strict_types=1);

function getSpacer(string $leftSide, string $rightSide, int $columns): string
{
    $leftLen = strlen(preg_replace('#\\x1b[[][^A-Za-z]*[A-Za-z]#', '', $leftSide));
    $rightLen = strlen(preg_replace('#\\x1b[[][^A-Za-z]*[A-Za-z]#', '', $rightSide));

    if ($leftLen > $columns) {
        $leftLen = $leftLen % $columns;
    }

    $spacer = str_repeat('.', $columns - (($leftLen + $rightLen + 2) % $columns));

    return " \033[1;30m{$spacer}\033[0m ";
}

function logit(string $msg, float $time): void
{
    $isXhr = (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') ? '[XHR] ' : '';
    $method = isset($_SERVER['REQUEST_METHOD']) ?
        strtoupper($_SERVER['REQUEST_METHOD']) : '';
    $statusCode = http_response_code();
    $statusColor = match (true) {
        $statusCode >= 200 && $statusCode < 300 => '32',
        $statusCode >= 300 && $statusCode < 400 => '34',
        $statusCode >= 400 && $statusCode < 500 => '33',
        $statusCode >= 500 => '31',
        default => '37',
    };
    $duration = sprintf('%.5f', round($time, 5));
    $columns = (int)getenv('CONIA_TERMINAL_COLUMNS');

    list($usec, $sec) = explode(' ', microtime());
    $usec = str_replace('0.', '.', $usec);
    $timestamp = date('H:i:s', (int)$sec) . substr($usec, 0, 3);
    $url = urldecode($msg);

    $leftSide =
        // timestamp
        "\033[0;37m{$timestamp}\033[0m " .
        // status code
        "\033[0;{$statusColor}m[{$statusCode}]\033[0m " .
        // request method
        "\033[0;33m{$method}\033[0m " .
        // request uri
        "\033[0;{$statusColor}m{$url}\033[0m";
    $rightSide =
        // xhr indicator
        "\033[0;36m{$isXhr}\033[0m" .
        // time
        "\033[0;37m{$duration}s\033[0m";

    error_log($leftSide . getSpacer($leftSide, $rightSide, $columns) . $rightSide);
}

if (PHP_SAPI !== 'cli') {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $publicDir = getenv('CONIA_DOCUMENT_ROOT');
    $url = urldecode(parse_url($uri, PHP_URL_PATH));

    $start = microtime(true);

    try {
        if ($publicDir) {
            // serve existing files as-is
            if (is_file($publicDir . $url)) {
                return false;
            }

            if (is_file($publicDir . rtrim($url, '/') . '/index.html')) {
                return false;
            }

            if ($url === '/phpinfo') {
                echo phpinfo();

                return true;
            }

            $_SERVER['SCRIPT_NAME'] = 'index.php';

            /** @psalm-suppress UnresolvableInclude */
            require_once $publicDir . '/index.php';

            return true;
        }
    } finally {
        logit($uri, microtime(true) - $start);
    }

    return false;
}
