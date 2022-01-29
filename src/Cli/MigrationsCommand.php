<?php

declare(strict_types=1);

namespace Chuck\Cli;

use Chuck\ConfigInterface;

abstract class MigrationsCommand extends \Chuck\Cli\Command
{
    protected function getMigrations(ConfigInterface $config): array
    {
        $migrations = [];
        $path = $config->path('migrations');
        $migrations = array_merge(
            $migrations,
            array_filter(glob("$path/*.sql"), 'is_file'),
            array_filter(glob("$path/*.php"), 'is_file'),
        );

        // Sort by file name and instead of full path
        uasort($migrations, function ($a, $b) {
            if (basename($a) == basename($b)) {
                return 0;
            }
            return (basename($a) < basename($b)) ? -1 : 1;
        });

        return $migrations;
    }

    protected function logMigration(\PDO $db, string $migration): void
    {
        $stmt = $db->prepare(
            'INSERT INTO migrations (migration) VALUES (:migration)'
        );
        $name = basename($migration);
        $stmt->bindParam(':migration', $name, \PDO::PARAM_STR);
        $stmt->execute();
    }
}
