<?php

declare(strict_types=1);

namespace Chuck\Util;


class Http
{
    public static function origin(): string
    {
        $https = $_SERVER['HTTPS'] ?? false ? true : false;
        $proto = $https ? 'https' : 'http';

        // Assume cli when HTTP_HOST ist not available
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $readPort = $_SERVER['SERVER_PORT'] ?? '';

        $port = match ($readPort) {
            '80' => '',
            '443' => '',
            '' => '',
            default => ':' . $readPort,
        };

        $origin = "$proto://$host$port";

        if (!filter_var($origin, FILTER_VALIDATE_URL)) {
            throw new \ValueError('Invalid origin');
        }

        return $origin;
    }

    public static function fullRequestUri(): string|false
    {
        return filter_var(
            self::origin() . $_SERVER['REQUEST_URI'],
            FILTER_VALIDATE_URL
        );
    }
}
