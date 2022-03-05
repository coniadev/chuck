<?php

declare(strict_types=1);

namespace Chuck\Memcached;

abstract class BaseWrapper
{
    protected mixed $conn;

    public function __construct(
        protected string $server,
        protected int $port,
    ) {
        $this->connect();
    }

    abstract protected function connect(): void;

    public function getConn(): mixed
    {
        return $this->conn;
    }

    public function get(string $key): mixed
    {
        return $this->conn->get($key);
    }

    public function delete(string $key, int $timeout = 0): bool
    {
        // NOTE: $timeout has no effect when \Memcache is used and always
        //       defaults to 0 in this case.
        //       see: https://www.php.net/manual/de/memcache.delete.php
        return $this->conn->delete($key, $timeout);
    }
}
