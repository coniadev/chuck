<?php

declare(strict_types=1);

namespace Chuck\Memcached;

use \InvalidArgumentException;
use \RuntimeException;
use Chuck\ConfigInterface;


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
                    throw new InvalidArgumentException('Memcached implementation does not exist');
            }
        } else {
            if (class_exists('\Memcached', false) && $preferMemcached) {
                $this->impl = new MemcachedWrapper($server, $port);
            } else {
                if (class_exists('\Memcache', false)) {
                    $this->impl = new MemcacheWrapper($server, $port);
                } else {
                    // @codeCoverageIgnoreStart
                    throw new RuntimeException('No memcached extension available');
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

    public function add(string $key, array|string $value, ?int $expire = null): bool
    {
        return $this->impl->add($key, $value, $this->getExpire($expire));
    }

    public function set(string $key, array|string $value, ?int $expire = null): bool
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
