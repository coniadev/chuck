<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use Chuck\Cli\CommandInterface;
use Chuck\ConfigInterface;
use Chuck\Database\{Database, DatabaseInterface};


abstract class Command implements CommandInterface
{
    protected function db(ConfigInterface $config, string $conn, string $sql): DatabaseInterface
    {
        return new Database($config->db($conn, $sql));
    }

    protected function logMigration(DatabaseInterface $db, string $migration): void
    {
        $name = basename($migration);
        $db->execute(
            'INSERT INTO migrations (migration) VALUES (:migration)',
            ['migration' => $name]
        )->run();
    }

    protected function getMigrations(ConfigInterface $config): array
    {
        $migrations = [];

        foreach ($config->migrations() as $path) {
            $migrations = array_merge(
                $migrations,
                array_filter(glob("$path/*.php"), 'is_file'),
                array_filter(glob("$path/*.sql"), 'is_file'),
                array_filter(glob("$path/*.tpql"), 'is_file'),
            );
        }

        // Sort by file name instead of full path
        uasort($migrations, function ($a, $b) {
            if (basename($a) == basename($b)) {
                return 0;
            }
            return (basename($a) < basename($b)) ? -1 : 1;
        });

        return $migrations;
    }
}
