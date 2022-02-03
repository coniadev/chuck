<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;
use Chuck\Hash;
use Chuck\Model\DatabaseInterface;
use Chuck\Util\Path;

class Database implements DatabaseInterface
{
    protected ConfigInterface $config;
    protected int $defaultFetchMode;
    protected bool $shouldPrint = false;
    protected bool $useMemcache = false;

    protected Hash $hash;
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
        // $this->hash = new Hash($config);
        $this->addScriptDirs($config->path('sql'));
        $this->fetchMode = $dbConf['fetchMode'] ?? PDO::FETCH_BOTH;
        $this->shouldPrint = $dbConf['print'];
    }

    public function shouldPrint(bool $shouldPrint): self
    {
        $this->shouldPrint = $shouldPrint;

        return $this;
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

    public function addScriptDirs(array|string $dirs): self
    {
        if (!is_array($dirs)) {
            $dirs = [$dirs];
        }

        $clean = [];
        $pathUtil = new Path($this->config);

        foreach ($dirs as $dir) {
            $dir = Path::realpath($dir);

            if (!$pathUtil->insideRoot($dir)) {
                throw new \InvalidArgumentException('SQL script path is outside of project root');
            }

            $clean[] = $dir;
        }

        $this->scriptPaths = array_merge($this->scriptPaths, $clean);

        return $this;
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

    public function __get($key): Folder
    {
        return new Folder($this, $key);
    }

    public function encode(int $id): string
    {
        return $this->hash->encode($id);
    }

    public function encodeList(
        iterable $list,
        array|string $hashKey,
        bool $asUid = false
    ): \Generator {
        if (is_array($hashKey)) {
            foreach ($list as $item) {
                foreach ($hashKey as $hk) {
                    $item[$hk] = $this->hash->encode($item[$hk]);
                }
                yield $item;
            }
        } else {
            if ($asUid) {
                $targetKey = 'uid';
            } else {
                $targetKey = $hashKey;
            }

            foreach ($list as $item) {
                $item[$targetKey] = $this->hash->encode($item[$hashKey]);
                yield $item;
            }
        }
    }

    public function decode(string $uid): int
    {
        return $this->hash->decode($uid);
    }
}
