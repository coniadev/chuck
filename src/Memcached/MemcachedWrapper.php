<?php

declare(strict_types=1);

namespace Chuck\Memcached;

class MemcachedWrapper extends BaseWrapper implements WrapperInterface
{
    protected function connect(): void
    {
        $this->conn = new \Memcached();
        $this->conn->addServer($this->server, $this->port);
    }

    public function add(string $key, mixed $value, int $expire): bool
    {
        return $this->conn->add($key, $value, $expire);
    }

    public function set(string $key, mixed $value, int $expire): bool
    {
        return $this->conn->set($key, $value, $expire);
    }
}
