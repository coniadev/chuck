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

        return "$proto://$host$port";
    }
}
