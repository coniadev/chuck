<?php

declare(strict_types=1);

namespace Chuck\Config;

use \InvalidArgumentException;


class Path
{
    public readonly string $public;
    /** @var array<string, string|array> */
    protected  array $paths;

    public function __construct(public readonly string $root)
    {
    }

    public function add(string $key, string $value): void
    {
        if (isset($this->paths[$key])) {
            if (is_string($this->paths[$key])) {
                $this->paths[$key] = [
                    $this->paths[$key],
                    $value,
                ];
            } else {
                $this->paths[$key][] = $value;
            }
        } else {
            $this->paths[$key] = $value;
        }
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
