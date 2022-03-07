<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDO;


trait LogsMigrations
{
    protected function logMigration(PDO $db, string $migration): void
    {
        $stmt = $db->prepare(
            'INSERT INTO migrations (migration) VALUES (:migration)'
        );
        $name = basename($migration);
        $stmt->bindParam(':migration', $name, PDO::PARAM_STR);
        $stmt->execute();
    }
}
