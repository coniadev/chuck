<?php

declare(strict_types=1);

use Chuck\ConfigInterface;

class Migrations extends Chuck\Cli\MigrationsCommand
{
    public static string $group = 'Database';
    public static string $title = 'Initialize the database tables';
    public static string $desc;

    public function run(ConfigInterface $config, string ...$args): void
    {
        $command = $args[0] ?? null;

        if ($command === 'add') {
            $this->add($config);
        } else {
            $this->migrate($config, $command === 'stacktrace', $command === 'dry');
        }
    }

    protected function add(ConfigInterface $config): void
    {
        $ts = date('YmdHis', time());
        $fileName = readline('Name of the migration: ');
        // fopen("testfile.txt", "w")
        $fileName = str_replace(' ', '_', $fileName);
        $fileName = str_replace('-', '_', $fileName);
        $fileName = $ts . '_' . strtolower($fileName);
        $ext = pathinfo($fileName, PATHINFO_EXTENSION);
        if (!$ext) {
            $fileName .= '.sql';
        }

        $migration = $config->path('migrations') .
            DIRECTORY_SEPARATOR .
            $fileName;

        $f = fopen($migration, 'w');
        fclose($f);
        echo "\nMigration created:\n$migration\n";
    }

    protected function migrate(
        ConfigInterface $config,
        bool $showStacktrace,
        bool $dryRun
    ): void {
        $db = $this->db($config);
        $db->beginTransaction();

        $appliedMigrations = $this->getAppliedMigrations($db);

        $applied = 0;
        foreach ($this->getMigrations($config) as $migration) {
            if (in_array(basename($migration), $appliedMigrations)) {
                continue;
            }

            $ext = pathinfo($migration, PATHINFO_EXTENSION);
            if ($ext == 'sql') {
                $this->migrateSQL($db, $migration, $showStacktrace);
            } else {
                $this->migratePHP($db, $migration, $showStacktrace);
            }

            $applied += 1;
        }

        if ($dryRun) {
            $db->rollback();
        } else {
            $db->commit();
        }

        if ($applied === 0) {
            echo "No migrations to apply\n";
        }
    }

    protected function getAppliedMigrations(PDO $db): array
    {
        $stmt = $db->prepare('SELECT migration FROM migrations;');
        $stmt->execute();
        return array_map(fn (array $mig): array => $mig['migration'], $stmt->fetchAll());
    }

    protected function migrateSQL(
        PDO $db,
        string $migration,
        bool $showStacktrace
    ): void {
        $script = file_get_contents($migration);
        if (!$script) {
            return;
        }

        try {
            $db->exec($script);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);
        } catch (PDOException $e) {
            $db->rollback();
            $this->showMessage($migration, $e, $showStacktrace);
            exit(1);
        }
    }

    protected function migratePHP(
        PDO $db,
        string $migration,
        bool $showStacktrace
    ): void {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);
        } catch (\Exception $e) {
            $this->showMessage($migration, $e, $showStacktrace);
        }
    }

    protected function showMessage(
        string $migration,
        ?object $e = null,
        bool $showStacktrace = false
    ): void {
        if ($e) {
            echo "\033[1;31mError\033[0m: while working on migration '\033[1;33m" .
                basename($migration) .
                "\033[0m'\n";
            echo $e->getMessage() . "\n";

            if ($showStacktrace) {
                echo $e->getTraceAsString() . "\n";
            }
            return;
        }

        echo "\033[1;32mSuccess\033[0m: Migration '\033[1;33m" .
            basename($migration) .
            "'\033[0m successfully applied\n";
    }
}

return new Migrations();
