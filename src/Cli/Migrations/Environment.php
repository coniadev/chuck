<?php

declare(strict_types=1);

namespace Chuck\Cli\Migrations;

use \PDO;
use Chuck\Cli\Opts;
use Chuck\Config;
use Chuck\ConfigInterface;
use Chuck\Database\{Database, DatabaseInterface};


class Environment
{
    public readonly string $conn;
    public readonly string $sql;
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
        // The `db` section from the config file.
        // If there is a plain 'db' entry in the config file, it is used
        // by default. If there are named additional connetions you want to
        // use, pass the identifier after the dot,
        // e. g. 'db.myconn' in the config must be '--conn myconn'
        $this->conn = $opts->get('--conn', Config::DEFAULT);
        // The `sql` section from the config file which points to sql file dirs.
        // The same idea applies to 'sql' as to 'db' above. 'sql' is used by default.
        // e. g. 'sql.otherscripts' in the config must be '--sql otherscripts'
        $this->sql = $opts->get('--sql', Config::DEFAULT);

        $this->showStacktrace = $opts->has('--stacktrace');
        $this->db = $this->db($config, $this->conn, $this->sql);
        $this->driver = $this->db->getPdoDriver();
        $this->convenience = in_array($this->driver, ['sqlite', 'mysql', 'pgsql']);
        $this->table = $config->get('migrationstable.name', 'migrations');
        $this->column = $config->get('migrationstable.name', 'migration');
        $this->config = $config;
    }

    public function db(ConfigInterface $config, string $conn, string $sql): DatabaseInterface
    {
        return new Database($config->db($conn, $sql));
    }

    public function getMigrations(ConfigInterface $config): array
    {
        $migrations = [];
        $migrationDirs = $config->migrations();

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
            if (basename($a) == basename($b)) {
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

    public function getMigrationsTableDDL(
        string $driver,
        string $table = 'migrations',
        string $column = 'migration',
    ): string|false {
        if ($driver === 'pqsql' && strpos($table, '.') !== false) {
            [$schema, $table] = explode('.', $table);
        } else {
            $schema = 'public';
        }

        switch ($driver) {
            case 'sqlite':
                return "CREATE TABLE $table (
    $column text NOT NULL,
    executed timestamp DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ($column)
);";
            case 'pgsql':
                return "CREATE TABLE $schema.$table (
    $column text NOT NULL,
    executed timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pk_$table PRIMARY KEY ($column)
);";
            case 'mysql':
                return "CREATE TABLE $table (
    $column varchar(255) NOT NULL,
    executed timestamp DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ($column)
);";
            default:
                return false;
        }
    }
}
