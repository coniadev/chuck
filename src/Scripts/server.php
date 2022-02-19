<?php

declare(strict_types=1);

class Server extends Chuck\Cli\Command
{
    public static string $group = 'General';
    public static string $title = 'Start the development server';
    public static string $desc = 'php run serve [<port>]';

    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $publicDir = $config->path('public');
        $port = (string)$config->get('port');

        if (isset($args[0]) && preg_match('/^[0-9]+$/', $args[0])) {
            $port = $args[0];
        }

        exec(
            "PUBLIC_DIR=$publicDir php -S localhost:$port " .
                "    -t $publicDir/ " .
                __DIR__ . "/support/server.php"
        );
    }
}

return new Server();
