<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Config\{Path, Log, Connection};

use const Chuck\STANDARD;


interface ConfigInterface
{
    public function app(): string;
    public function debug(): bool;
    public function env(): string;
    public function has(string $key): bool;
    public function get(string $key, mixed $default = null): mixed;
    public function path(): Path;
    public function db(string $connection = STANDARD, string $sql = STANDARD): Connection;
    public function log(): Log;
    public function templates(): array;
    public function migrations(): array;
    public function scripts(): array;
}
