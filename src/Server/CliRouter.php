<?php

// phpcs:ignoreFile

declare(strict_types=1);

function logit(string $msg): void
{
    $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') ? ' [XHR]' : '';
    $method = isset($_SERVER['REQUEST_METHOD']) ?
        strtoupper($_SERVER['REQUEST_METHOD']) : '';
    $statusCode = http_response_code();
    $color = match (true) {
        $statusCode >= 200 && $statusCode < 300 => '32',
        $statusCode >= 300 && $statusCode < 400 => '34',
        $statusCode >= 400 && $statusCode < 500 => '33',
        $statusCode >= 500 => '31',
        default => '37',
    };

    error_log(
        sprintf(
            "\033[1;{$color}m(%s)\033[0m: \033[1;33m%s \033[0m\033[1;{$color}m%s\033[0m\033[1;36m%s\033[0m",
            (string)$statusCode,
            $method,
            urldecode($msg),
            $isAjax,
        )
    );
}

if (PHP_SAPI !== 'cli') {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $publicDir = getenv('DOCUMENT_ROOT');
    $url = urldecode(parse_url($uri, PHP_URL_PATH));

    try {
        if ($publicDir) {
            // serve existing files as-is
            if (is_file($publicDir . $url)) {
                return false;
            }

            if (is_file($publicDir . rtrim($url, '/') . '/index.html')) {
                return false;
            }

            if ($url === '/server-php-info') {
                echo phpinfo();

                return true;
            }

            $_SERVER['SCRIPT_NAME'] = 'index.php';

            /** @psalm-suppress UnresolvableInclude */
            require_once $publicDir . '/index.php';

            return true;
        }
    } finally {
        logit($uri);
    }

    return false;
}
