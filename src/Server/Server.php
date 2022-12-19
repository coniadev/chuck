<?php

declare(strict_types=1);

namespace Conia\Chuck\Server;

use Conia\Cli\Command;
use Conia\Cli\Opts;

/** @psalm-suppress PropertyNotSetInConstructor */
class Server extends Command
{
    protected string $name = 'server';
    protected string $description = 'Serve the application on the builtin PHP server';

    public function __construct(
        protected readonly string $docroot,
        protected readonly int $port = 1983,
    ) {
    }

    public function run(): string|int
    {
        $docroot = $this->docroot;
        $port = (string)$this->port;

        $opts = new Opts();
        $port = $opts->get('-p', $opts->get('--port', $port));

        exec(
            "DOCUMENT_ROOT=$docroot php -S localhost:$port " .
                "    -t $docroot" . DIRECTORY_SEPARATOR . ' ' .
                __DIR__ . DIRECTORY_SEPARATOR . 'CliRouter.php'
        );

        return 0;
    }
}
