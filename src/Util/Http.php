<?php

declare(strict_types=1);

namespace Conia\Chuck\Util;

use \ValueError;
use Conia\Chuck\Error\ExitException;


class Http
{
    public static function origin(): string
    {
        $proto = $_SERVER['HTTPS'] ?? false ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $origin = "$proto://$host";

        if (!filter_var($origin, FILTER_VALIDATE_URL)) {
            throw new ValueError('Invalid origin');
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

    public static function redirect(string $url, int $code = 302): never
    {
        header('Location: ' . $url, true, $code);

        throw new ExitException();
    }
}
