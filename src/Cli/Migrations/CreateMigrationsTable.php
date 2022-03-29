<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \Throwable;
use Chuck\Cli\CommandInterface;
use Chuck\ConfigInterface;


ini_set('register_argc_argv', true);
global $argv;


class CreateMigrationsTable implements CommandInterface
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    public function run(ConfigInterface $config): mixed
    {
        $env = $env = new Environment($config);

        print("HINAAAAAA\n");

        if (!$env->convenience) {
            echo "PDO driver '$env->driver' not supported. Aborting\n";

            return false;
        }

        if ($env->checkIfMigrationsTableExists($env->db)) {
            echo "Table '$env->table' already exists. Aborting\n";
            return false;
        } else {
            $ddl = $env->getMigrationsTableDDL($env->driver, $env->table, $env->column);

            if ($ddl) {
                try {
                    $env->db->execute($ddl)->run();
                    echo "\033[1;32mSuccess\033[0m: Created table '$env->table'\n";
                    return true;
                } catch (Throwable $e) {
                    echo "\033[1;31mError\033[0m: While trying to create table '$env->table'\n";
                    echo $e->getMessage() . PHP_EOL;

                    if ($env->showStacktrace) {
                        echo $e->getTraceAsString() . PHP_EOL;
                    }
                    return false;
                }
            } else {
                echo "Driver '$env->driver' is not supported.\n";
            }

            return false;
        }
    }
}
