<?php

declare(strict_types=1);

namespace Chuck;

use Psr\Log\LoggerInterface;


interface ConfigInterface
{
    public function __construct(array $config);
    public function get(string $key, mixed $default = null): mixed;
    public function path(string $key): string;
    public function paths(string $key): array;
    public function register(string $interface, string $class): void;
    public function registry(string $key): string;
    public function registered(string $key): bool;
    public function addRenderer(string $key, string $class): void;
    public function renderer(string $key): string;
    public function templates(): array;
    public function migrations(): array;
    public function sql(): array;
    public function scripts(): array;
    public function debug(): bool;
    public function env(): string;

    public function addLogger(LoggerInterface $logger): void;
    public function getLogger(): ?LoggerInterface;
}
