<?php

declare(strict_types=1);

namespace Chuck\Config;

use \InvalidArgumentException;
use \ValueError;


class Path
{
    use PathTrait;

    public readonly string $root;
    public readonly string $public;
    protected readonly array $paths;

    public function __construct(string $root, array $paths)
    {
        $this->root = $root;

        // Public directory containing the static assets and index.php
        // If it is not set look for a directory named 'public' in path.root
        if (!isset($paths['public'])) {
            $this->public = $this->preparePath('public');

            if (!is_dir($this->public)) {
                throw new ValueError(
                    'Configuration error: public directory is not set and could not be determined'
                );
            }
        } else {
            $this->public = $this->preparePath($paths['public']);
        }

        $this->paths = array_map(
            function ($path) {
                if (is_string($path)) {
                    return $this->preparePath($path);
                }

                return array_map(fn ($p) => $this->preparePath($p), $path);
            },
            array_filter(
                $paths,
                fn ($key) => $key !== 'root' && $key !== 'public',
                ARRAY_FILTER_USE_KEY,
            )
        );
    }

    public function get(string $key, string $default = ''): string
    {
        $value = $this->paths[$key] ?? false;

        if ($value && is_string($value)) {
            return $value;
        }

        if ($value && is_array($value)) {
            throw new InvalidArgumentException(
                "Path id '$key' contains a list of paths. Use Config::paths(\$key)"
            );
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new InvalidArgumentException(
            "Path id '$key' is not present in configuration"
        );
    }

    public function list(string $key, array $default = []): array
    {
        $value = $this->paths[$key] ?? false;

        if ($value && is_array($value)) {
            return $value;
        }

        if ($value && is_string($value)) {
            throw new InvalidArgumentException(
                "Paths id '$key' contains a single path. Use Config::path(\$key)"
            );
        }

        if (func_num_args() > 1) {
            return $default;
        }

        throw new InvalidArgumentException(
            "Paths id '$key' is not present in configuration"
        );
    }
}
