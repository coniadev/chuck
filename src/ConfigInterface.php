<?php

declare(strict_types=1);

namespace Chuck;

interface ConfigInterface
{
    public function __construct(array $config);
    public function get(string $key);
    public function path(string $key);
    public function register(string $key, mixed $value): void;
    public function registry(string $key): string;
    public function responseClass(): string;
    public function addRenderer(string $key, string $class): void;
    public function renderer(string $key): string;
}
