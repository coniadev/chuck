<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDOException;
use \Throwable;
use Chuck\Cli\Opts;
use Chuck\Database\DatabaseInterface;
use Chuck\ConfigInterface;


class Migrations extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected DatabaseInterface $db;
    protected const STARTED = 'start';
    protected const ERROR = 'error';
    protected const WARNING = 'warning';
    protected const SUCCESS = 'success';

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
                echo "    php run create-migrations-table\n\n";
                echo "If you need to change the table or column name add the following ";
                echo "settings to your configuration\n\n:";
                echo "\$yourConfig = [\n";
                echo "    ...\n";
                echo "    'migrationstable.name' => '<yourtablename>',\n";
                echo "    'migrationstable.column' => '<yourcolumnname>',\n";
                echo "    ...\n";
                echo "];\n";
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
        $this->begin($db);
        $appliedMigrations = $this->getAppliedMigrations($db);
        $result = self::STARTED;
        $numApplied = 0;

        foreach ($this->getMigrations($config) as $migration) {
            if (in_array(basename($migration), $appliedMigrations)) {
                continue;
            }

            if (filesize($migration) === 0) {
                $this->showEmptyMessage($migration);
                continue;
            }

            switch (pathinfo($migration, PATHINFO_EXTENSION)) {
                case 'sql';
                    $result = $this->migrateSQL($db, $migration, $showStacktrace);
                    break;
                case 'tpql';
                    // $result = $this->migrateTPQL($db, $migration, $showStacktrace);
                    break;
                case 'php';
                    $result = $this->migratePHP($db, $migration, $showStacktrace);
                    break;
            }

            if ($result === self::ERROR) {
                break;
            }

            if ($result === self::SUCCESS) {
                $numApplied++;
            }
        }

        return $this->finish($db, $result, $apply, $numApplied);
    }

    protected function begin(DatabaseInterface $db): void
    {
        if ($this->supportsTransactions($db)) {
            $db->begin();
        }
    }

    protected function finish(
        DatabaseInterface $db,
        string $result,
        bool $apply,
        int $numApplied,
    ) {
        $plural = $numApplied > 1 ? 's' : '';

        if ($this->supportsTransactions($db)) {
            if ($result === self::ERROR) {
                $db->rollback();
                echo "\nDue to errors no migrations applied\n";
                return false;
            }

            if ($numApplied === 0) {
                $db->rollback();
                echo "\nNo migrations applied\n";
                return true;
            }

            if ($apply) {
                $db->commit();
                echo "\n$numApplied migration$plural successfully applied\n";
                return true;
            } else {
                echo "\n\033[1;31mNotice\033[0m: Test run only\033[0m";
                echo "\nWould apply $numApplied migration$plural. ";
                echo "Use the switch --apply to make it happen\n";
                $db->rollback();
                return true;
            }
        } else {
            if ($result === self::ERROR) {
                $db->rollback();
                echo "\n$numApplied migration$plural applied until the error occured\n";
                return false;
            }

            if ($numApplied > 0) {
                echo "\n$numApplied migration$plural successfully applied\n";
                return true;
            }

            echo "\nNo migrations applied\n";
            return true;
        }

        return true;
    }

    protected function supportsTransactions(DatabaseInterface $db): bool
    {
        switch ($this->driver) {
            case 'sqlite':
                return true;
            case 'pgsql':
                return true;
            case 'mysql':
                return false;
            default:
                return false;
        }
    }

    protected function getAppliedMigrations(DatabaseInterface $db): array
    {
        $migrations = $db->execute("SELECT $this->column FROM $this->table;")->all();
        return array_map(fn (array $mig): string => $mig['migration'], $migrations);
    }

    protected function migrateSQL(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): string {
        $script = file_get_contents($migration);

        if (empty(trim($script))) {
            $this->showEmptyMessage($migration);
            return self::WARNING;
        }

        try {
            $db->execute($script)->run();
            $this->logMigration($db, $migration);
            $this->showMessage($migration);

            return self::SUCCESS;
        } catch (PDOException $e) {
            $this->showMessage($migration, $e, $showStacktrace);

            return self::ERROR;
        }
    }

    protected function migrateTPQL(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): string {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->showMessage($migration, $e, $showStacktrace);

            return self::ERROR;
        }
    }

    protected function migratePHP(
        DatabaseInterface $db,
        string $migration,
        bool $showStacktrace
    ): string {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->showMessage($migration, $e, $showStacktrace);

            return self::ERROR;
        }
    }

    protected function showEmptyMessage(string $migration): void
    {
        echo "\033[33mWarning\033[0m: Migration '\033[1;33m" .
            basename($migration) .
            "'\033[0m is empty. Skipped\n";
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
