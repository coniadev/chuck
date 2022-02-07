<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Path;


class Config implements ConfigInterface
{
    protected array $config;

    public function __construct(array $config)
    {
        $defaults = require 'defaults.php';

        $this->config = array_replace_recursive(
            $defaults,
            $config,
        );
    }

    public function get(string $key, $default = null)
    {
        if (func_num_args() > 1) {
            return $this->config[$key] ?? $default;
        }

        if (!array_key_exists($key, $this->config)) {
            throw new \InvalidArgumentException("Chuck Error: The configuration key '$key' does not exist");
        }

        return $this->config[$key];
    }

    public function path(string $key): string|array
    {
        $path = $this->config['path'][$key];

        if (is_array($path)) {
            return array_map(function ($p) {
                return Path::realpath($p);
            }, $path);
        }

        return Path::realpath($this->config['path'][$key]);
    }
}
