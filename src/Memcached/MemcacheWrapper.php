<?php

declare(strict_types=1);

namespace Chuck\Memcached;


class MemcacheWrapper extends BaseWrapper implements WrapperInterface
{
    protected function connect(): void
    {
        $this->conn = new \Memcache();
        $this->conn->connect($this->server, $this->port);
    }

    public function add(string $key, mixed $value, int $expire): bool
    {
        // TODO: Using 0 as flag value, compression is not used
        //       Should we use MEMCACHE_COMPRESSED?
        return $this->conn->add($key, $value, 0, $expire);
    }

    public function set(string $key, mixed $value, int $expire): bool
    {
        // TODO: See self::add
        return $this->conn->set($key, $value, 0, $expire);
    }
}
