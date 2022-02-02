<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;
use Chuck\Hash;
use Chuck\RequestInterface;
use Chuck\Model\DatabaseInterface;

class Database
{
    protected int $defaultFetchMode;
    protected bool $shouldPrint = false;
    protected bool $useMemcache = false;

    protected Hash $hash;
    protected ?PDO $conn = null;
    protected ?array $memcachedConfig = null;
    protected ?\Memcached $memcached = null;
    protected array $scriptPaths = [];

    public function __construct(
        protected string $dsn,
        protected ?string $username = null,
        protected ?string $password = null,
        protected ?array $options = null,
    ) {
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $dbConf = $config->get('db');
        $db = new Database($dbConf['dsn'], $dbConf['username'] ?? null, $dbConf['password'] ?? null);
        // $this->hash = new Hash($config);
        $db->addScriptPath($config->path('sql'));
        $db->fetchMode = $dbConf['fetchMode'] ?? PDO::FETCH_DEFAULT;
        $db->fetchMode = $dbConf['fetchMode'] ?? PDO::FETCH_DEFAULT;
        $db->shouldPrint = $dbConf['print'];

        return $db;
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

    protected function addScriptPath(array|string $paths): self
    {
        if (!is_array($paths)) {
            $paths = [$paths];
        }

        $this->scriptPaths = array_merge($this->scriptPaths, $paths);

        return $this;
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
