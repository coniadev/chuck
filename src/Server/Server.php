<?php

declare(strict_types=1);

namespace Conia\Chuck\Server;

use Conia\Chuck\Config;
use Conia\Cli\Command;
use Conia\Cli\Opts;

class Server extends Command
{
    protected string $group = 'General';
    protected string $title = 'Start the development server';
    protected string $description = 'php run serve [-p | --port <port>]';

    public function __construct(protected readonly Config $config)
    {
    }

    public function run(): string|int
    {
        $publicDir = $this->config->get('path.public', getcwd() . DIRECTORY_SEPARATOR . 'public');

        if (!is_dir($publicDir)) {
            if (is_file(getcwd() . DIRECTORY_SEPARATOR . 'index.php')) {
                $publicDir = getcwd();
            } else {
                echo "The directory to serve from could not be determined. " .
                    "Either create the directory `./public`, put your `index.php` " .
                    "to the path where the `run` script resides or set the path " .
                    "via config: \n\n    \$config->set('path.public', '/your/path')\n";

                return 1;
            }
        }

        $port = (string)$config->get('server.port', '1983');

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
