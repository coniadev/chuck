<?php

declare(strict_types=1);

namespace Conia\Chuck\Server;

use Conia\Cli\Command;
use Conia\Cli\Opts;

/** @psalm-api */
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
        $filter = $opts->get('-f', $opts->get('--filter', ''));
        $quiet = $opts->has('-q');

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open(
            "DOCUMENT_ROOT={$docroot} php -S localhost:{$port} " .
                ($quiet ? '-q ' : '') .
                "    -t {$docroot}" . DIRECTORY_SEPARATOR . ' ' . __DIR__ . DIRECTORY_SEPARATOR . 'CliRouter.php ',
            $descriptors,
            $pipes
        );

        if (is_resource($process)) {
            while (!feof($pipes[1])) {
                $output = fgets($pipes[2], 1024);
                if (strlen($output) === 0) {
                    break;
                }

                if (!str_contains($output, '127.0.0.1')) {
                    $pos = strpos($output, ']');
                    list($usec, $sec) = explode(' ', microtime());
                    $usec = str_replace('0.', '.', $usec);

                    if (!$filter || !preg_match($filter, substr($output, strpos($output, '/')))) {
                        echo '[' . date('H:i:s', (int)$sec) . substr($usec, 0, 3) . '] ' . substr($output, $pos + 2);
                    }
                }
            }

            fclose($pipes[1]);
            proc_close($process);
        }

        return 0;
    }
}
