<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \Throwable;
use Chuck\Database\DatabaseInterface;
use Chuck\Cli\Opts;
use Chuck\ConfigInterface;

use const Chuck\STANDARD;

ini_set('register_argc_argv', true);
global $argv;


class CreateMigrationsTable extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected DatabaseInterface $db;

    public function run(ConfigInterface $config): mixed
    {
        $opts = new Opts();
        $conn = $opts->get('--conn', STANDARD);
        $sql = $opts->get('--sql', STANDARD);
        $stacktrace = $opts->has('--stacktrace');

        $db = $this->db($config, $conn, $sql);
        $driver = $db->getPdoDriver();
        $convenience = in_array($driver, ['sqlite', 'mysql', 'pgsql']);
        $table = $config->get('migrationstable.name', 'migrations');
        $column = $config->get('migrationstable.name', 'migration');

        if (!$convenience) {
            echo "PDO driver '$driver' not supported. Aborting\n";
            return false;
        }

        if ($this->checkIfMigrationsTableExists($db)) {
            echo "Table '$table' already exists. Aborting\n";
            return false;
        } else {
            $ddl = $this->getMigrationsTableDDL($driver, $table, $column);

            if ($ddl) {
                try {
                    $db->execute($ddl)->run();
                    echo "\033[1;32mSuccess\033[0m: created table '$table'.\n";
                } catch (Throwable $e) {
                    echo "\033[1;31mError\033[0m: while trying to create table '$table'.\n";
                    echo $e->getMessage() . PHP_EOL;

                    if ($stacktrace) {
                        echo $e->getTraceAsString() . PHP_EOL;
                    }
                }
            } else {
                echo "Driver '$driver' is not supported.\n";
            }

            return false;
        }
    }
}
