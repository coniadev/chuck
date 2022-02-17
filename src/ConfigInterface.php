<?php

declare(strict_types=1);

namespace Chuck;

interface ConfigInterface
{
    public function __construct(array $config);
    public function get(string $key, $default = null);
    public function path(string $key);
    public function register(string $interface, string $class): void;
    public function registry(string $key): string;
    public function addRenderer(string $key, string $class): void;
    public function renderer(string $key): string;
}
