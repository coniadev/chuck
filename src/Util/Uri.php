<?php

declare(strict_types=1);

namespace Conia\Chuck\Util;

use ValueError;
use Conia\Chuck\Error\ExitException;

class Uri
{
    public static function scheme(): string
    {
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            return $_SERVER['HTTP_X_FORWARDED_PROTO'];
        } else {
            if (isset($_SERVER['REQUEST_SCHEME'])) {
                return $_SERVER['REQUEST_SCHEME'];
            } elseif (isset($_SERVER['HTTPS'])) {
                return strtolower($_SERVER['HTTPS']) === 'on' ? 'https' : 'http';
            }
        }

        return 'http';
    }

    public static function host(bool $stripPort = false): string
    {
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';

        if ($stripPort) {
            // Returns the host without the port
            return trim(strtok($host, ':'));
        }

        return $host;
    }

    public static function origin(): string
    {
        $scheme = self::scheme();
        $host = self::host();
        $origin = ($scheme ? "$scheme:" : $scheme) . "//$host";

        if (!filter_var($origin, FILTER_VALIDATE_URL)) {
            throw new ValueError('Invalid origin');
        }

        return $origin;
    }

    public static function path(bool $stripQuery = false): string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '';

        if ($stripQuery) {
            // Returns the path without query string
            return trim(strtok($uri, '?'));
        }

        return $uri;
    }

    public static function url(bool $stripQuery = false): string|false
    {
        return filter_var(
            self::origin() . self::path($stripQuery),
            FILTER_VALIDATE_URL
        );
    }

    public static function redirect(string $url, int $code = 302): never
    {
        header('Location: ' . $url, true, $code);

        throw new ExitException();
    }
}
