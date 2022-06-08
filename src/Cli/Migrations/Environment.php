<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDO;
use Chuck\Cli\Opts;
use Chuck\Config;
use Chuck\Config\Connection;
use Chuck\ConfigInterface;
use Chuck\Database\{Database, DatabaseInterface};


class Environment
{
    public readonly Connection $conn;
    public readonly string $driver;
    public readonly bool $showStacktrace;
    public readonly bool $convenience;
    public readonly string $table;
    public readonly string $column;
    public readonly DatabaseInterface $db;
    public readonly ConfigInterface $config;

    public function __construct(ConfigInterface $config)
    {
        $opts = new Opts();
        $conn = $config->connection($opts->get('--conn', Config::DEFAULT));
        $this->conn = $conn;
        $this->showStacktrace = $opts->has('--stacktrace');
        $this->db = $this->db($this->conn);
        $this->driver = $this->db->getPdoDriver();
        $this->convenience = in_array($this->driver, ['sqlite', 'mysql', 'pgsql']);
        $this->table = $conn->migrationsTable();
        $this->columnMigration = $conn->migrationsColumnMigration();
        $this->columnApplied = $conn->migrationsColumnApplied();
        $this->config = $config;
    }

    public function db(Connection $conn): DatabaseInterface
    {
        return new Database($conn);
    }

    public function getMigrations(Connection $conn): array
    {
        $migrations = [];
        $migrationDirs = $conn->migrations();

        if (count($migrationDirs) === 0) {
            echo "\033[1;31mNotice\033[0m: No migration directories defined in configuration\033[0m\n";
        }

        foreach ($migrationDirs as $path) {
            $migrations = array_merge(
                $migrations,
                array_filter(glob("$path/*.php"), 'is_file'),
                array_filter(glob("$path/*.sql"), 'is_file'),
                array_filter(glob("$path/*.tpql"), 'is_file'),
            );
        }

        // Sort by file name instead of full path
        uasort($migrations, function ($a, $b) {
            if (basename($a) === basename($b)) {
                return 0;
            }
            return (basename($a) < basename($b)) ? -1 : 1;
        });

        return $migrations;
    }

    public function checkIfMigrationsTableExists(
        DatabaseInterface $db,
        string $table = 'migrations',
    ): bool {
        $driver = $db->getPdoDriver();

        if ($driver === 'pqsql' && strpos($table, '.') !== false) {
            [$schema, $table] = explode('.', $table);
        } else {
            $schema = 'public';
        }

        $query = match ($driver) {
            'sqlite' => "
                SELECT count(*) AS available
                FROM sqlite_master
                WHERE type='table'
                AND name='migrations';",

            'mysql' => "
                SELECT count(*) AS available
                FROM information_schema.tables
                WHERE table_name='$table';",

            'pgsql' => "
                SELECT count(*) AS available
                FROM pg_tables
                WHERE schemaname = '$schema'
                AND tablename = '$table';",
            default => false,
        };

        if ($query && ($db->execute($query)->one(PDO::FETCH_ASSOC)['available'] ?? 0) === 1) {
            return true;
        }

        return false;
    }

    public function getMigrationsTableDDL(): string|false
    {
        if ($this->driver === 'pgsql' && strpos($this->table, '.') !== false) {
            [$schema, $table] = explode('.', $this->table);
        } else {
            $schema = 'public';
            $table = $this->table;
        }
        $columnMigration = $this->columnMigration;
        $columnApplied = $this->columnApplied;

        switch ($this->driver) {
            case 'sqlite':
                return "CREATE TABLE $table (
    $columnMigration text NOT NULL,
    $columnApplied timestamp DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ($columnMigration)
);";
            case 'pgsql':
                return "CREATE TABLE $schema.$table (
    $columnMigration text NOT NULL,
    $columnApplied timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pk_$table PRIMARY KEY ($columnMigration)
);";
            case 'mysql':
                return "CREATE TABLE $table (
    $columnMigration varchar(255) NOT NULL,
    $columnApplied timestamp DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ($columnMigration)
);";
            default:
                return false;
        }
    }
}
