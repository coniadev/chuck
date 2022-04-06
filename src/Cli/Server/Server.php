<?php

declare(strict_types=1);

namespace Chuck\Cli\Server;

use Chuck\ConfigInterface;
use Chuck\Cli\{CommandInterface, Opts};


class Server implements CommandInterface
{
    public static string $group = 'General';
    public static string $title = 'Start the development server';
    public static string $desc = 'php run serve [<port>]';

    public function run(ConfigInterface $config): string|int
    {
        $publicDir = $config->path()->public;

        if ($config->has('port')) {
            $port = (string)$config->get('port');
        } else {
            $port = '1983';
        }

        $opts = new Opts();
        $port = $opts->get('-p', $opts->get('--port', $port));

        if (preg_match('/^[0-9]+$/', $port)) {
            exec(
                "PUBLIC_DIR=$publicDir php -S localhost:$port " .
                    "    -t $publicDir" . DIRECTORY_SEPARATOR . ' ' .
                    __DIR__ . DIRECTORY_SEPARATOR . 'Router.php'
            );

            return 0;
        }

        return "No valid port given\n";
    }
}
