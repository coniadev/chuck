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
        $port = (string)$config->get('devport');

        if (isset($args[0]) && is_integer($args[0])) {
            $port = $args[0];
        }

        $reloadMode = null;

        if ($config->get('devel')) {
            $reloadMode = 'hmr';

            foreach ($args as $arg) {
                if ($arg === 'live' || $arg === 'livereload') {
                    $reloadMode = 'livereload';
                }
            }
        }

        exec(
            "RELOAD_MODE=$reloadMode PUBLIC_DIR=$publicDir php -S localhost:$port " .
                "    -t $publicDir/ " .
                __DIR__ . "/support/server.php"
        );
    }
}

return new Server();