<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDO;
use \PDOException;
use \Throwable;
use Chuck\ConfigInterface;


class Migrations extends Command
{
    public static string $group = 'Database';
    public static string $title = 'Apply missing database migrations';
    public static string $desc;

    public function run(ConfigInterface $config, string ...$args): mixed
    {
        $command = $args[0] ?? null;

        return $this->migrate($config, $command === 'stacktrace', $command === 'dry');
    }

    protected function migrate(
        ConfigInterface $config,
        bool $showStacktrace,
        bool $dryRun
    ): bool {
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
            return false;
        }

        return true;
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
