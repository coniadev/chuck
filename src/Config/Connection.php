<?php

declare(strict_types=1);

namespace Chuck\Config;

use \PDO;
use \RuntimeException;


class Connection
{
    public readonly string $driver;
    public readonly string $dsn;
    public readonly ?string $username;
    public readonly ?string $password;
    public readonly array $options;
    public readonly int $fetchMode;
    public readonly bool $debug;
    public readonly bool $memcached;
    public readonly array $sqlDirs;

    public function __construct(
        protected array $connection,
        protected string|array $sql
    ) {
        $this->dsn = $connection['dsn'];
        $this->username = $connection['username'] ?? null;
        $this->password = $connection['password'] ?? null;
        $this->options = $connection['options'] ?? [];
        $this->fetchMode = $connection['fetchmode'] ?? PDO::FETCH_BOTH;
        $this->print = $connection['print'] ?? false;
        $this->memcached = $connection['memcached'] ?? false;
        $this->driver = $this->getDriver($this->dsn);
        $this->sqlDirs = $this->getDirs();
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
