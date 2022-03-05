<?php

declare(strict_types=1);

namespace Chuck\Memcached;

interface WrapperInterface
{
    public function __construct(string $server, int $port);
    public function get(string $key): mixed;
    public function add(string $key, mixed $value, int $expire): bool;
    public function set(string $key, mixed $value, int $expire): bool;
    public function delete(string $key, int $timeout = 0): bool;
    public function getConn(): mixed;
}
