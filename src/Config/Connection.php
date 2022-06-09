<?php

declare(strict_types=1);

namespace Chuck\Config;

use \PDO;
use \RuntimeException;
use \ValueError;
use Chuck\Util\Arrays;

class Connection
{
    use PathTrait;

    protected readonly string $driver;
    protected array $sql;
    protected array $migrations;

    protected string $migrationsTable = 'migrations';
    protected string $migrationsColumnMigration = 'migration';
    protected string $migrationsColumnApplied = 'applied';

    public function __construct(
        protected readonly string $dsn,
        string|array $sql,
        string|array $migrations = null,
        protected readonly ?string $username = null,
        protected readonly ?string $password = null,
        protected readonly array $options = [],
        protected readonly int $fetchMode = PDO::FETCH_BOTH,
        protected readonly bool $print = false

    ) {
        $this->driver = $this->readDriver($this->dsn);
        $this->sql = $this->readDirs($sql);
        $this->migrations = $this->readDirs($migrations ?? []);
    }

    protected function readDriver(string $dsn): string
    {
        $driver = explode(':', $dsn)[0];

        if (in_array($driver, PDO::getAvailableDrivers())) {
            return $driver;
        }

        throw new RuntimeException('PDO driver not supported: ' . $driver);
    }

    protected function prepareDirs(array $entry): array
    {
        $dirs = [];

        // Add sql scripts for the current pdo driver.
        // Should be the first in the list as they
        // may have platform specific queries.
        if (array_key_exists($this->driver, $entry)) {
            $dirs[] = $this->preparePath($entry[$this->driver]);
        }

        // Add sql scripts for all platforms
        if (array_key_exists('all', $entry)) {
            $dirs[] = $this->preparePath($entry['all']);
        }

        return $dirs;
    }

    /**
     * Adds the sql script paths from configuration.
     *
     * Script paths are ordered last in first out (LIFO).
     * Which means the last path added is the first one searched
     * for a SQL script.
     */
    protected function readDirs(string|array $sql): array
    {
        if (is_string($sql)) {
            return [$this->preparePath($sql)];
        }

        if (Arrays::isAssoc($sql)) {
            return $this->prepareDirs($sql);
        }

        $dirs = [];

        foreach ($sql as $entry) {
            if (is_string($entry)) {
                array_unshift($dirs, $this->preparePath($entry));
                continue;
            }

            if (Arrays::isAssoc($entry)) {
                $dirs = array_merge($this->prepareDirs($entry), $dirs);
                continue;
            }

            throw new ValueError(
                "The 'sql' setting in the config file must be " .
                    "a string or an associative array"
            );
        }

        return $dirs;
    }

    public function setMigrationsTable(string $table): void
    {
        $this->migrationsTable = $table;
    }

    public function setMigrationsColumnMigration(string $column): void
    {
        $this->migrationsColumnMigration = $column;
    }

    public function setMigrationsColumnApplied(string $column): void
    {
        $this->migrationsColumnApplied = $column;
    }

    public function migrationsTable(): string
    {
        if ($this->driver === 'pgsql') {
            // PostgreSQL table names can contain a schema
            if (preg_match('/^([a-zA-Z0-9_]+\.)?[a-zA-Z0-9_]+$/', $this->migrationsTable)) {
                return $this->migrationsTable;
            }
        } else {
            if (preg_match('/^[a-zA-Z0-9_]+$/', $this->migrationsTable)) {
                return $this->migrationsTable;
            }
        }

        throw new ValueError('Invalid migrations table name: ' . $this->migrationsTable);
    }

    protected function getColumnName(string $column): string
    {
        if (preg_match('/^[a-zA-Z0-9_]+$/', $column)) {
            return $column;
        }

        throw new ValueError('Invalid migrations table column name: ' . $column);
    }

    public function migrationsColumnMigration(): string
    {
        return $this->getColumnName($this->migrationsColumnMigration);
    }

    public function migrationsColumnApplied(): string
    {
        return $this->getColumnName($this->migrationsColumnApplied);
    }

    public function dsn(): string
    {
        return $this->dsn;
    }

    public function username(): ?string
    {
        return $this->username;
    }

    public function password(): ?string
    {
        return $this->password;
    }

    public function options(): array
    {
        return $this->options;
    }

    public function print(): bool
    {
        return $this->print;
    }
    public function driver(): string
    {
        return $this->driver;
    }

    public function fetchMode(): int
    {
        return $this->fetchMode;
    }

    public function migrations(): array
    {
        return $this->migrations;
    }

    public function sql(): array
    {
        return $this->sql;
    }
}
