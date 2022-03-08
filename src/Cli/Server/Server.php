<?php

declare(strict_types=1);

namespace Chuck\Cli\Server;

use Chuck\ConfigInterface;
use Chuck\Cli\CommandInterface;


class Server implements CommandInterface
{
    public static string $group = 'General';
    public static string $title = 'Start the development server';
    public static string $desc = 'php run serve [<port>]';

    public function run(ConfigInterface $config): mixed
    {
        $publicDir = $config->path()->public;

        if ($config->has('port')) {
            $port = (string)$config->get('port');
        } else {
            $port = '1983';
        }

        if (isset($args[0]) && preg_match('/^[0-9]+$/', $args[0])) {
            $port = $args[0];
        }

        exec(
            "PUBLIC_DIR=$publicDir php -S localhost:$port " .
                "    -t $publicDir" . DIRECTORY_SEPARATOR . ' ' .
                __DIR__ . DIRECTORY_SEPARATOR . 'support' .
                DIRECTORY_SEPARATOR . 'server.php'
        );

        return 1;
    }
}
