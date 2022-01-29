<?php

declare(strict_types=1);

namespace Chuck\Model;

use \PDO;

use Chuck\ConfigInterface;
use Chuck\Hash;
use Chuck\RequestInterface;

class Database
{
    public RequestInterface $request;
    public ConfigInterface $config;
    public $fetchMode;
    public $printSql = false;

    protected Hash $hash;
    protected PDO $conn;
    protected ?\Memcached $memcached = null;
    protected array $scriptPaths;

    public function __construct(RequestInterface $request, int $fetchMode)
    {
        $this->request = $request;
        $config = $request->config;
        $this->config = $config;
        $this->fetchMode = $fetchMode;
        $this->hash = new Hash($request);
        $this->connect();
        $this->setScriptPaths();
        $this->printSql = $config->get('print_sql');
    }


    protected function setScriptPaths(): void
    {
        $dirs = $this->config->path('sql');

        if (!is_array($dirs)) {
            $dirs = [$dirs];
        }

        // TODO: add additional paths
        $this->scriptPaths = array_merge($dirs, []);
    }

    public function getScriptPaths(): array
    {
        return $this->scriptPaths;
    }

    protected function connect(): void
    {
        $db = $this->config->get('db');
        $dbms = $db['dbms'];
        $host = $db['host'];
        $port = $db['port'];
        $dbname = $db['name'];
        $username = $db['user'];
        $password = $db['pass'];

        $memcachedConfig = $this->config->get('memcached');
        if ($memcachedConfig['use']) {
            $this->connectMemcached($memcachedConfig);
        }

        $this->conn = new PDO(
            "$dbms:host=$host;port=$port;dbname=$dbname",
            $username,
            $password
        );

        // Always throw an exception when an error occures
        $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Allow getting the number of rows
        $this->conn->setAttribute(PDO::ATTR_CURSOR, PDO::CURSOR_SCROLL);
        // deactivate native prepared statements by default
        $this->conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
        // do not alter casing of the columns from sql
        $this->conn->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);
    }

    protected function connectMemcached(array $config): void
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

    public function setFetchMode(int $mode): void
    {
        $this->fetchMode = $mode;
    }

    public function getFetchMode(): int
    {
        return $this->fetchMode;
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
