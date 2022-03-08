<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \Throwable;
use Chuck\Database\DatabaseInterface;
use Chuck\ConfigInterface;


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
        $this->init($config);

        if (!$this->convenience) {
            echo "PDO driver '$this->driver' not supported. Aborting\n";
            return false;
        }

        if ($this->checkIfMigrationsTableExists($this->db)) {
            echo "Table '$this->table' already exists. Aborting\n";
            return false;
        } else {
            $ddl = $this->getMigrationsTableDDL($this->driver, $this->table, $this->column);

            if ($ddl) {
                try {
                    $this->db->execute($ddl)->run();
                    echo "\033[1;32mSuccess\033[0m: created table '$this->table'.\n";
                } catch (Throwable $e) {
                    echo "\033[1;31mError\033[0m: while trying to create table '$this->table'.\n";
                    echo $e->getMessage() . PHP_EOL;

                    if ($this->showStacktrace) {
                        echo $e->getTraceAsString() . PHP_EOL;
                    }
                }
            } else {
                echo "Driver '$this->driver' is not supported.\n";
            }

            return false;
        }
    }
}
