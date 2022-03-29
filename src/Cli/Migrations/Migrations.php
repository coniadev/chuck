<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDOException;
use \RuntimeException;
use \Throwable;
use Chuck\Cli\{Opts, CommandInterface};
use Chuck\Database\DatabaseInterface;
use Chuck\ConfigInterface;


class Migrations implements CommandInterface
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    protected readonly Environment $env;
    protected const STARTED = 'start';
    protected const ERROR = 'error';
    protected const WARNING = 'warning';
    protected const SUCCESS = 'success';

    public function run(ConfigInterface $config): string|int
    {
        /**
         * @psalm-suppress InaccessibleProperty
         *
         * TODO: At the time of writing Psalm did not support
         * readonly properties which are not initialized in the
         * constructor. Recheck on occasion.
         * https://github.com/vimeo/psalm/issues/7608
         */
        $this->env = $env = new Environment($config);
        $opts = new Opts();

        if (!$env->convenience || $env->checkIfMigrationsTableExists($env->db)) {
            return $this->migrate($env->db, $config, $opts->has('--stacktrace'), $opts->has('--apply'));
        } else {
            $ddl = $env->getMigrationsTableDDL($env->driver);

            if ($ddl) {
                echo "Migrations table does not exist. For '$env->driver' it should look like:\n\n";
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
                echo "Driver '$env->driver' is not supported.\n";
            }

            return 1;
        }
    }

    protected function migrate(
        DatabaseInterface $db,
        ConfigInterface $config,
        bool $showStacktrace,
        bool $apply
    ): int {
        $this->begin($db);
        $appliedMigrations = $this->getAppliedMigrations($db);
        $result = self::STARTED;
        $numApplied = 0;

        foreach ($this->env->getMigrations($config) as $migration) {
            if (in_array(basename($migration), $appliedMigrations)) {
                continue;
            }

            if (!$this->supportedByDriver($migration)) {
                continue;
            }

            $script = file_get_contents($migration);

            if (empty(trim($script))) {
                $this->showEmptyMessage($migration);
                $result = self::WARNING;
                continue;
            }

            switch (pathinfo($migration, PATHINFO_EXTENSION)) {
                case 'sql';
                    $result = $this->migrateSQL($db, $migration, $script, $showStacktrace);
                    break;
                case 'tpql';
                    $result = $this->migrateTPQL($db, $config, $migration, $showStacktrace);
                    break;
                case 'php';
                    $result = $this->migratePHP($db, $config, $migration, $showStacktrace);
                    break;
                default:
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
    ): int {
        $plural = $numApplied > 1 ? 's' : '';

        if ($this->supportsTransactions($db)) {
            if ($result === self::ERROR) {
                $db->rollback();
                echo "\nDue to errors no migrations applied\n";
                return 1;
            }

            if ($numApplied === 0) {
                $db->rollback();
                echo "\nNo migrations applied\n";
                return 0;
            }

            if ($apply) {
                $db->commit();
                echo "\n$numApplied migration$plural successfully applied\n";
                return 0;
            } else {
                echo "\n\033[1;31mNotice\033[0m: Test run only\033[0m";
                echo "\nWould apply $numApplied migration$plural. ";
                echo "Use the switch --apply to make it happen\n";
                $db->rollback();
                return 0;
            }
        } else {
            if ($result === self::ERROR) {
                echo "\n$numApplied migration$plural applied until the error occured\n";
                return 1;
            }

            if ($numApplied > 0) {
                echo "\n$numApplied migration$plural successfully applied\n";
                return 0;
            }

            echo "\nNo migrations applied\n";
            return 0;
        }
    }

    protected function supportsTransactions(): bool
    {
        switch ($this->env->driver) {
            case 'sqlite':
                return true;
            case 'pgsql':
                return true;
            case 'mysql':
                return false;
        }

        throw new RuntimeException('Database driver not supported');
    }

    protected function getAppliedMigrations(DatabaseInterface $db): array
    {
        $table = $this->env->table;
        $column = $this->env->column;
        $migrations = $db->execute("SELECT $column FROM $table;")->all();
        return array_map(fn (array $mig): string => $mig['migration'], $migrations);
    }

    /**
     * Returns if the given migration is driver specific
     */
    protected function supportedByDriver(string $migration): bool
    {
        // First checks if there are brackets in the filename.
        if (preg_match('/\[[a-z]{3,8}\]/', $migration)) {
            // We have found a driver specific migration.
            // Check if it matches the current driver.
            if (preg_match('/\[' . $this->env->driver . '\]/', $migration)) {
                return true;
            }

            return false;
        }

        // This is no driver specific migration
        return true;
    }

    protected function migrateSQL(
        DatabaseInterface $db,
        string $migration,
        string $script,
        bool $showStacktrace
    ): string {
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
        ConfigInterface $config,
        string $migration,
        bool $showStacktrace
    ): string {
        try {
            $load = function (string $migrationPath, array $context = []): void {
                // Hide $migrationPath. Could be overwritten if $context['templatePath'] exists.
                $____migration_path____ = $migrationPath;

                extract($context);

                /** @psalm-suppress UnresolvableInclude */
                include $____migration_path____;
            };

            $error = null;
            $context = [
                'driver' => $db->getPdoDriver(),
                'db' => $db,
                'config' => $config,
            ];

            ob_start();

            try {
                $load($migration, $context);
            } catch (Throwable $e) {
                $error = $e;
            }

            $script = ob_get_contents();
            ob_end_clean();

            if ($error !== null) {
                throw $error;
            }

            if (empty(trim($script))) {
                $this->showEmptyMessage($migration);
                return self::WARNING;
            }

            return $this->migrateSQL($db, $migration, $script, $showStacktrace);
        } catch (Throwable $e) {
            $this->showMessage($migration, $e, $showStacktrace);

            return self::ERROR;
        }
    }

    protected function migratePHP(
        DatabaseInterface $db,
        ConfigInterface $config,
        string $migration,
        bool $showStacktrace
    ): string {
        try {
            /** @psalm-suppress UnresolvableInclude */
            $migObj = require $migration;
            $migObj->run($db, $config);
            $this->logMigration($db, $migration);
            $this->showMessage($migration);

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->showMessage($migration, $e, $showStacktrace);

            return self::ERROR;
        }
    }

    protected function logMigration(DatabaseInterface $db, string $migration): void
    {
        $name = basename($migration);
        $db->execute(
            'INSERT INTO migrations (migration) VALUES (:migration)',
            ['migration' => $name]
        )->run();
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
            "\033[0m' successfully applied\n";
    }
}
