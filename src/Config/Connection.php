<?php

declare(strict_types=1);

namespace Chuck\Config;

use \PDO;
use \RuntimeException;


class Connection
{
    public readonly string $driver;
    public readonly array $sqlDirs;

    public function __construct(
        protected string|array $sql,
        public readonly string $dsn,
        public readonly ?string $username = null,
        public readonly ?string $password = null,
        public readonly array $options = [],
        public readonly int $fetchMode = PDO::FETCH_BOTH,
        public readonly bool $print = false
    ) {
        $this->driver = $this->getDriver($this->dsn);
        $this->sqlDirs = $this->getDirs();
    }

    public static function fromArray(
        array $connection,
        string|array $sql
    ): self {
        return new self(
            $sql,
            $connection['dsn'],
            $connection['username'] ?? null,
            $connection['password'] ?? null,
            $connection['options'] ?? [],
            $connection['fetchmode'] ?? PDO::FETCH_BOTH,
            $connection['print'] ?? false,
        );
    }

    protected function getDriver(string $dsn): string
    {
        $driver = explode(':', $dsn)[0];

        if (in_array($driver, PDO::getAvailableDrivers())) {
            return $driver;
        }

        throw new RuntimeException('PDO driver not supported: ' . $driver);
    }

    /**
     * Adds the sql script paths from configuration.
     *
     * Script paths are ordered last in first out (LIFO).
     * Which means the last path added is the first one searched
     * for a SQL script.
     */
    protected function getDirs(): array
    {
        $dirs = [];

        if (is_string($this->sql)) {
            return [$this->sql];
        }

        // Add sql scripts for the current pdo driver.
        // Should be the first in the list as they
        // may have platform specific queries.
        if (array_key_exists($this->driver, $this->sql)) {
            $dirs[] = $this->sql[$this->driver];
        }

        // Add sql scripts for all platforms
        if (array_key_exists('all', $this->sql)) {
            $dirs[] = $this->sql['all'];
        }

        return $dirs;
    }
}
