<?php

declare(strict_types=1);

namespace Chuck;

use Psr\Log\LoggerInterface;
use Chuck\Config;
use Chuck\Config\Connection;


interface ConfigInterface
{
    public function app(): string;
    public function debug(): bool;
    public function env(): string;
    public function root(): string;
    public function public(): string;
    public function has(string $key): bool;
    public function get(string $key, mixed $default = null): mixed;
    public function logger(): ?LoggerInterface;
    public function connection(string $name = Config::DEFAULT,): Connection;
    public function scripts(): array;
    public function renderers(): array;
}
