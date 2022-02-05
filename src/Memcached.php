<?php

declare(strict_types=1);

namespace Chuck;

interface WrapperInterface
{
    public function __construct(string $server, int $port);
    public function get(string $key): mixed;
    public function add(string $key, mixed $value, int $expires = 0): bool;
    public function set(string $key, mixed $value, int $expires = 0): bool;
    public function delete(string $key, int $timeout = 0): bool;
    public function getConn(): mixed;
}


abstract class BaseWrapper
{
    protected mixed $conn;

    public function __construct(
        protected string $server,
        protected int $port,
    ) {
        $this->connect($server, $port);
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


class MemcachedWrapper extends BaseWrapper implements WrapperInterface
{
    protected function connect(): void
    {
        $this->conn = new \Memcached();
        $this->conn->addServer($this->server, $this->port);
    }

    public function add(string $key, mixed $value, int $expires = 0): bool
    {
        return $this->conn->add($key, $value, $expires);
    }

    public function set(string $key, mixed $value, int $expires = 0): bool
    {
        return $this->conn->set($key, $value, $expires);
    }
}


class MemcacheWrapper extends BaseWrapper implements WrapperInterface
{
    protected function connect(): void
    {
        $this->conn = new \Memcache();
        $this->conn->connect($this->server, $this->port);
    }

    public function add(string $key, mixed $value, int $expires = 0): bool
    {
        // TODO: Using 0 as flag value, compression is not used
        //       Should we use MEMCACHE_COMPRESSED?
        return $this->conn->add($key, $value, 0, $expires);
    }

    public function set(string $key, mixed $value, int $expires = 0): bool
    {
        // TODO: See self::add
        return $this->conn->set($key, $value, 0, $expires);
    }
}


class Memcached implements MemcachedInterface
{
    protected WrapperInterface $impl;

    public function __construct(
        protected string $server = 'localhost',
        protected int $port = 11211,
        string $implementation = null
    ) {
        if ($implementation) {
            $this->impl = new $implementation($server, $port);
        } else {
            if (class_exists('\Memcached', false)) {
                $this->impl = new MemcachedWrapper($server, $port);
            } else {
                if (class_exists('\Memcache', false)) {
                    $this->impl = new MemcacheWrapper($server, $port);
                } else {
                    throw new \ErrorException('No memcached extension available');
                }
            }
        }
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $mc = new self('localhost', 11211, \Memcached::class);

        return $mc;
    }

    public function getConn(): mixed
    {
        return $this->impl->getConn();
    }

    public function get(string $key): mixed
    {
        return $this->impl->get($key);
    }

    public function delete(string $key, int $timeout = 0): bool
    {
        return $this->impl->delete($key, $timeout);
    }

    public function add(string $key, mixed $value, int $expires = 0): bool
    {
        return $this->impl->add($key, $value, $expires);
    }

    public function set(string $key, mixed $value, int $expires = 0): bool
    {
        return $this->impl->set($key, $value, $expires);
    }
}
