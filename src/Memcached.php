<?php

declare(strict_types=1);

namespace Chuck;

interface WrapperInterface
{
    public function __construct(string $server, int $port);
    public function get(string $key): mixed;
    public function add(string $key, mixed $value, int $expire): bool;
    public function set(string $key, mixed $value, int $expire): bool;
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


class Memcached implements MemcachedInterface
{
    protected WrapperInterface $impl;

    public function __construct(
        string $server = 'localhost',
        int $port = 11211,
        ?string $implementation = null,
        protected ?int $expire = null,
        protected bool $preferMemcached = true,
    ) {
        if ($implementation) {
            switch ($implementation) {
                case 'Memcached':
                    $this->impl = new MemcachedWrapper($server, $port);
                    break;
                case 'Memcache':
                    $this->impl = new MemcacheWrapper($server, $port);
                    break;
                default:
                    throw new \InvalidArgumentException('Memcached implementation does not exist');
            }
        } else {
            if (class_exists('\Memcached', false) && $preferMemcached) {
                $this->impl = new MemcachedWrapper($server, $port);
            } else {
                if (class_exists('\Memcache', false)) {
                    $this->impl = new MemcacheWrapper($server, $port);
                } else {
                    // @codeCoverageIgnoreStart
                    throw new \RuntimeException('No memcached extension available');
                    // @codeCoverageIgnoreEnd
                }
            }
        }
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $settings = $config->get('memcached');

        $mc = new self(
            server: $settings['host'] ?? 'localhost',
            port: $settings['port'] ?? 11211,
            implementation: $settings['implementation'] ?? null,
            expire: $settings['expire'] ?? null,
        );

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

    public function add(string $key, mixed $value, ?int $expire = null): bool
    {
        return $this->impl->add($key, $value, $this->getExpire($expire));
    }

    public function set(string $key, mixed $value, ?int $expire = null): bool
    {
        return $this->impl->set($key, $value, $this->getExpire($expire));
    }

    public function getExpire(?int $expire): int
    {
        if ($expire === null) {
            return $this->expire ?? 0;
        }

        return $expire;
    }
}
