<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDOException;
use \Throwable;
use Chuck\Database\DatabaseInterface;
use Chuck\Cli\Opts;
use Chuck\ConfigInterface;

use const Chuck\STANDARD;

ini_set('register_argc_argv', true);
global $argv;


class Migrations extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected DatabaseInterface $db;

    public function run(ConfigInterface $config): mixed
    {
        $opts = new Opts();
        // The `db` section from the config file.
        // If there is a plain 'db' entry in the config file, it is used
        // by default. If there are named additional connetions you want to
        // use, pass the identifier after the dot,
        // e. g. 'db.myconn' in the config must be '--conn myconn'
        $conn = $opts->get('--conn', STANDARD);
        // The `sql` section from the config file which points to sql file dirs.
        // The same idea applies to 'sql' as to 'db' above. 'sql' is used by default.
        // e. g. 'sql.otherscripts' in the config must be '--sql otherscripts'
        $sql = $opts->get('--sql', STANDARD);
        $db = $this->db($config, $conn, $sql);
        $driver = $db->getPdoDriver();
        $noconvenience = !in_array($driver, ['sqlite', 'mysql', 'pgsql']);

        if ($noconvenience || $this->checkIfMigrationsTableExists($db)) {
            return $this->migrate($db, $config, $opts->has('--stacktrace'), $opts->has('--apply'));
        } else {
            $ddl = $this->getMigrationsTableDDL($driver);

            if ($ddl) {
                echo "Migrations table does not exist. For '$driver' it should look like:\n\n";
                echo $ddl;
                echo "\n\nIf you want to create the table above, simply run\n\n";
                echo "    php run create-migrations-table\n";
            } else {
                echo "Driver '$driver' is not supported.\n";
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
