<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDOException;
use \Throwable;
use Chuck\Database\Database;
use Chuck\Cli\{CommandInterface, Opts};
use Chuck\ConfigInterface;

ini_set('register_argc_argv', true);
global $argv;

class Migrations implements CommandInterface
{
    use GetsMigrations;
    use LogsMigrations;

    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected string $conn;
    protected string $sql;


    public function run(ConfigInterface $config): mixed
    {

        exit(0);
        // return $this->migrate($config, $command === 'stacktrace', $command === 'apply');
    }

    protected function migrate(
        ConfigInterface $config,
        bool $showStacktrace,
        bool $apply
    ): bool {
        $db = $this->db($config);
        $db->begin();

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

    protected function getAppliedMigrations(Database $db): array
    {
        $migrations = $db->execute('SELECT migration FROM migrations;')->all();
        return array_map(fn (array $mig): array => $mig['migration'], $migrations);
    }

    protected function migrateSQL(
        Database $db,
        string $migration,
        bool $showStacktrace
    ): void {
        $script = file_get_contents($migration);
        if (!$script) {
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

    protected function migratePHP(
        Database $db,
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

    protected function db(ConfigInterface $config): Database
    {
        return new Database($config->db($this->conn, $this->sql));
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

    protected function checkIfMigrationsTableExists(Database $db): bool
    {
        $query = match ($db->getPdoDriver()) {
            'sqlite' => "SELECT count(*) AS available FROM sqlite_master WHERE type='table' AND name='migrations';",
            'mysql' => "SELECT count(*) AS available FROM information_schema.tables WHERE table_name='migrations';",
            'pgsql' => 'SELECT',
        };

        return true;
    }

    protected function printCreateMigrationDDL(Database $db): void
    {
        echo 'CREATE TABLE migrations';
    }
}
