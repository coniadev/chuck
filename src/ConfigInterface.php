<?php

declare(strict_types=1);

namespace Chuck;

use Psr\Log\LoggerInterface;
use Chuck\Config;
use Chuck\Config\{Connection, Scripts};


interface ConfigInterface
{
    public function app(): string;
    public function debug(): bool;
    public function env(): string;
    public function has(string $key): bool;
    public function get(string $key, mixed $default = null): mixed;
    public function logger(): ?LoggerInterface;
    public function connection(string $name = Config::DEFAULT,): Connection;
    public function scripts(): Scripts;
    public function renderers(): array;
}
