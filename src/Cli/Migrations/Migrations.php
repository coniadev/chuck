<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDOException;
use \Throwable;
use Chuck\Config;
use Chuck\Cli\Opts;
use Chuck\Database\DatabaseInterface;
use Chuck\ConfigInterface;


class Migrations extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected DatabaseInterface $db;

    public function run(ConfigInterface $config): mixed
    {
        $opts = new Opts();
        $this->init($config);

        if (!$this->convenience || $this->checkIfMigrationsTableExists($this->db)) {
            return $this->migrate($this->db, $config, $opts->has('--stacktrace'), $opts->has('--apply'));
        } else {
            $ddl = $this->getMigrationsTableDDL($this->driver);

            if ($ddl) {
                echo "Migrations table does not exist. For '$this->driver' it should look like:\n\n";
                echo $ddl;
                echo "\n\nIf you want to create the table above, simply run\n\n";
                echo "    php run create-migrations-table\n";
            } else {
                echo "Driver '$this->driver' is not supported.\n";
            }

            return false;
        }
    }

    protected function migrate(
        DatabaseInterface $db,
        ConfigInterface $config,
        bool $showStacktrace,
        bool $apply
    ): bool {
        $db->begin();

        $appliedMigrations = $this->getAppliedMigrations($db);
        $applied = 0;

        foreach ($this->getMigrations($config) as $migration) {
            if (in_array(basename($migration), $appliedMigrations)) {
                continue;
            }

            switch (pathinfo($migration, PATHINFO_EXTENSION)) {
                case 'sql';
                    $this->migrateSQL($db, $migration, $showStacktrace);
                    break;
                case 'tpql';
                    $this->migrateTPQL($db, $migration, $showStacktrace);
                    break;
                case 'php';
                    $this->migratePHP($db, $migration, $showStacktrace);
                    break;
            }

            $applied += 1;
        }

        if ($apply) {
            $db->commit();
        } else {
            $db->rollback();
        }

        if ($applied === 0) {
            echo "No migrations to apply\n";
            return false;
        }

        return true;
    }

    protected function getAppliedMigrations(DatabaseInterface $db): array
    {
        $migrations = $db->execute('SELECT migration FROM migrations;')->all();
        return array_map(fn (array $mig): array => $mig['migration'], $migrations);
    }

    protected function migrateSQL(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): void {
        $script = file_get_contents($migration);

        if (empty(trim($script))) {
            return;
        }

        try {
            $db->execute($script)->run();
            $this->logMigration($db, $migration);
            $this->showMessage($migration);
        } catch (PDOException $e) {
            $db->rollback();
            $this->showMessage($migration, $e, $showStacktrace);
            exit(1);
        }
    }

    protected function migrateTPQL(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): void {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);
        } catch (Throwable $e) {
            $this->showMessage($migration, $e, $showStacktrace);
        }
    }

    protected function migratePHP(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): void {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);
        } catch (Throwable $e) {
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
