<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;
use Chuck\Model\DatabaseInterface;
use Chuck\Model\QueryInterface;
use Chuck\Util\Arrays;
use Chuck\Util\Path;


class Database implements DatabaseInterface
{
    protected ConfigInterface $config;
    protected int $defaultFetchMode;
    protected bool $shouldPrint = false;
    protected bool $useMemcache = false;

    protected ?PDO $conn = null;
    protected ?array $memcachedConfig = null;
    protected ?\Memcached $memcached = null;
    protected array $scriptPaths = [];
    protected int $fetchMode;

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        $dbConf = $config->get('db');
        $this->dsn = $dbConf['dsn'];
        $this->username = $dbConf['username'] ?? null;
        $this->password = $dbConf['password'] ?? null;
        $this->addScriptDirs($config->path('sql'));
        $this->fetchMode = $dbConf['fetchMode'] ?? PDO::FETCH_BOTH;
        $this->shouldPrint = $dbConf['print'];
    }

    public function defaultFetchMode(int $fetchMode): self
    {
        $this->fetchMode = $fetchMode;

        return $this;
    }

    public function memcachedConfig(array $settings): self
    {
        $this->memcachedConfig = $settings;

        return $this;
    }

    /**
     * Adds a single or multiple paths to the list of script paths.
     *
     * Script paths are ordered last in first out (LIFO).
     * Which means the last path added is the first one searched
     * for a SQL script.
     */
    public function addScriptDirs(array|string $dirs): self
    {
        if (!is_array($dirs)) {
            $dirs = [$dirs];
        }

        $pathUtil = new Path($this->config);

        foreach ($dirs as $dir) {
            $dir = Path::realpath($dir);

            if (!$pathUtil->insideRoot($dir)) {
                throw new \InvalidArgumentException('SQL script path is outside of project root');
            }

            array_unshift($this->scriptPaths, $dir);
        }

        return $this;
    }

    public function setPrintScript(bool $shouldPrint): self
    {
        $this->shouldPrint = $shouldPrint;

        return $this;
    }

    public function shouldPrintScript(): bool
    {
        return $this->shouldPrint;
    }

    public function getScriptDirs(): array
    {

        return $this->scriptPaths;
    }

    public function getFetchmode(): int
    {

        return $this->fetchMode;
    }

    public function connect(): self
    {
        if ($this->conn) {
            return $this;
        }

        if ($this->memcachedConfig) {
            $this->connectMemcached($this->memcachedConfig);
        }

        $this->conn = new PDO($this->dsn, $this->username, $this->password);

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

    protected function connectMemcached(?array $config): void
    {
        $this->memcached = new \Memcached();
        $this->memcached->setOption(\Memcached::OPT_BINARY_PROTOCOL, true);
        $this->memcached->addServer(
            $config['host'],
            $config['port']
        ) or die('Cannot connect to memcached server!');
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

    public function getConn(): \PDO
    {
        $this->connect();
        return $this->conn;
    }

    public function getMemcached(): ?\Memcached
    {
        return $this->memcached;
    }

    public function execute(string $query, ...$args): QueryInterface
    {
        return new Query($this, $query, $args);
    }

    public function __get($key): Folder
    {
        $exists = false;

        foreach ($this->scriptPaths as $path) {
            $exists = is_dir($path . DIRECTORY_SEPARATOR . $key);

            if ($exists) break;
        }

        if (!$exists) {
            throw new \UnexpectedValueException('The SQL folder does not exist: ' . $key);
        }

        return new Folder($this, $key);
    }
}
