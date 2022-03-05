<?php

declare(strict_types=1);

namespace Chuck\Database;

use \PDO;

use Chuck\ConfigInterface;
use Chuck\Database\DatabaseInterface;
use Chuck\Database\QueryInterface;
use Chuck\Config\Connection;


class Database implements DatabaseInterface
{
    protected ConfigInterface $appConfig;
    protected Connection $connConfig;
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected PDO $conn;
    protected ?\Chuck\Memcached $memcached = null;
    protected readonly string $memcachedPrefix;
    protected bool $print = false;


    public function __construct(
        ConfigInterface $config,
        protected string $connection = 'default',
        protected string $sql = 'default',
    ) {
        $this->appConfig = $config;
        $this->connConfig = $config->db($connection, $sql);
        $this->print = $this->connConfig->print;
        $this->memcachedPrefix = $config->app() . '/sql/';
    }

    public function setPrint(bool $print): self
    {
        $this->print = $print;

        return $this;
    }

    public function shouldPrint(): bool
    {
        return $this->print;
    }

    public function getFetchMode(): int
    {
        return $this->connConfig->fetchMode;
    }

    public function getPdoDriver(): string
    {
        return $this->connConfig->driver;
    }

    public function getSqlDirs(): array
    {
        return $this->connConfig->sqlDirs;
    }

    public function connect(): self
    {
        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (isset($this->conn)) {
            return $this;
        }

        if ($this->appConfig->get('memcached', false)) {
            $this->memcached = \Chuck\Memcached::fromConfig($this->appConfig);
        }

        $this->conn = new PDO(
            $this->connConfig->dsn,
            $this->connConfig->username,
            $this->connConfig->password,
            $this->connConfig->options,
        );

        // Always throw an exception when an error occures
        $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Allow getting the number of rows
        $this->conn->setAttribute(PDO::ATTR_CURSOR, PDO::CURSOR_SCROLL);
        // deactivate native prepared statements by default
        $this->conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
        // do not alter casing of the columns from sql
        $this->conn->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);

        return $this;
    }

    public function begin(): bool
    {
        $this->connect();
        return $this->conn->beginTransaction();
    }

    public function commit(): bool
    {
        return $this->conn->commit();
    }

    public function rollback(): bool
    {
        return $this->conn->rollback();
    }

    public function getConn(): PDO
    {
        $this->connect();
        return $this->conn;
    }

    public function getMemcached(): ?\Chuck\Memcached
    {
        return $this->memcached;
    }

    public function getMemcachedPrefix(): string
    {
        return $this->memcachedPrefix;
    }

    public function execute(string $query, mixed ...$args): QueryInterface
    {
        return new Query($this, $query, new Args($args));
    }

    public function __get(string $key): Folder
    {
        $exists = false;

        foreach ($this->connConfig->sqlDirs as $path) {
            $exists = is_dir($path . DIRECTORY_SEPARATOR . $key);

            if ($exists) break;
        }

        if (!$exists) {
            throw new \UnexpectedValueException('The SQL folder does not exist: ' . $key);
        }

        return new Folder($this, $key);
    }
}
