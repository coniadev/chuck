<?php

declare(strict_types=1);

namespace Chuck;


interface MemcachedInterface
{
    public function __construct(
        string $server,
        int $port,
        string $implementation = null
    );
    public function get(string $key): mixed;
    public function add(string $key, mixed $value, int $expires = 0): bool;
    public function set(string $key, mixed $value, int $expires = 0): bool;
    public function delete(string $key, int $timeout = 0): bool;
}
