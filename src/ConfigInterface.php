<?php

declare(strict_types=1);

namespace Chuck;


interface ConfigInterface
{
    public function __construct(array $config);
    public function get(string $key, mixed $default = null): mixed;
    public function path(string $key): string;
    public function pathOrNull(string $key): ?string;
    public function paths(string $key): array;
    public function templates(): array;
    public function migrations(): array;
    public function sql(): array;
    public function scripts(): array;
    public function debug(): bool;
    public function env(): string;
}
