<?php

// phpcs:ignoreFile

declare(strict_types=1);

function logit(string $msg): void
{
    $hostPort = '[' .
        ($_SERVER['REMOTE_ADDR'] ?? '<no-addr>') .
        ']:' .
        ($_SERVER['REMOTE_PORT'] ?? '<no-port>');

    $isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') ? '[XHR]' : '';
    $method = isset($_SERVER['REQUEST_METHOD']) ?
        strtoupper($_SERVER['REQUEST_METHOD']) : '';

    error_log(
        sprintf(
            "%s \033[1;33m%s%s:\033[0m \033[1;32m%s\033[0m",
            $hostPort,
            $method,
            $isAjax,
            urldecode($msg)
        )
    );
}


if (PHP_SAPI !== 'cli') {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $publicDir = getenv('DOCUMENT_ROOT');
    $url = urldecode(parse_url($uri, PHP_URL_PATH));

    // patch SCRIPT_NAME and pass the request to index.php
    logit($uri);

    // serve existing files as-is
    if ($publicDir) {
        if (is_file($publicDir . $url)) {
            return false;
        }

        if (is_file($publicDir . rtrim($url, '/') . '/index.html')) {
            return false;
        }

        $_SERVER['SCRIPT_NAME'] = 'index.php';

        /** @psalm-suppress UnresolvableInclude */
        require_once $publicDir . '/index.php';
        return true;
    } else {
        return false;
    }
}
