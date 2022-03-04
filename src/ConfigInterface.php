<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Config\{Path, Templates, Log, Connection};


interface ConfigInterface
{
    public function app(): string;
    public function debug(): bool;
    public function env(): string;
    public function get(string $key, mixed $default = null): mixed;
    public function path(): Path;
    public function templates(): Templates;
    public function db(string $connection, string $sql): Connection;
    public function log(): Log;
    public function scripts(): array;
}
