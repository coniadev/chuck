<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\ConfigInterface;

class Path
{
    public function __construct(ConfigInterface $config = null)
    {
        $this->config = $config;
    }

    public function insideRoot(string $path): bool
    {
        $root = $this->config->path('root');

        return str_starts_with(self::realpath($path), $root);
    }

    public static function realpath(string $path): string
    {
        $path = str_replace('//', '/', $path);
        $segments = explode('/', $path);
        $out = [];

        foreach ($segments as $segment) {
            if ($segment == '.') {
                continue;
            }

            if ($segment == '..') {
                array_pop($out);
                continue;
            }

            $out[] = $segment;
        }

        return implode('/', $out);
    }
}
