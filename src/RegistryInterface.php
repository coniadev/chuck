<?php

declare(strict_types=1);

namespace Chuck;


interface RegistryInterface
{
    public function add(string $key, string|object $entry): void;
    public function has(string $key): bool;
    public function get(string $key): string;
    public function new(string $key, mixed ...$args): object;
    public function obj(string $key): object;
}
