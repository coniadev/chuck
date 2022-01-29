<?php

declare(strict_types=1);

namespace Chuck;

class Config implements ConfigInterface
{
    protected array $config;

    public function __construct(array $config);
    {
        $defaults = require 'defaults.php';

        $this->config = array_replace_recursive(
            $defaults,
            $config,
        );
    }

    public function get(string $key)
    {
        return $this->config[$key];
    }

    public function getOr(string $key, $default)
    {
        return $this->config[$key] ?? $default;
    }

    public function path(string $key): string|array
    {
        $path = $this->config['path'][$key];

        if (is_array($path)) {
            return array_map(function ($p) {
                return Util::realpath($p);
            }, $path);
        }

        return Util::realpath($this->config['path'][$key]);
    }

    public function di(string $key): string
    {
        return $this->config['di'][$key];
    }

    public function renderer(string $key): string
    {
        return $this->config['renderer'][$key];
    }
}
