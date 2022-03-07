<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use Chuck\Database\DatabaseInterface;


trait LogsMigrations
{
    protected function logMigration(DatabaseInterface $db, string $migration): void
    {
        $name = basename($migration);
        $db->execute(
            'INSERT INTO migrations (migration) VALUES (:migration)',
            ['migration' => $name]
        )->run();
    }
}
