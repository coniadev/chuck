<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Util\Path as PathUtil;


class Path
{
    public function __construct(protected string $root)
    {
    }

    public function insideRoot(string $path): bool
    {
        $root = $this->config->path('root');

        return self::inside($root, $path);
    }

    protected function preparePath(string $root, string $path): string
    {
        $path = PathUtil::realpath($path);

        if (!PathUtil::isAbsolute($path)) {
            $path = $root . DIRECTORY_SEPARATOR . $path;
        }

        if (str_starts_with($path, $root)) {
            return $path;
        }

        throw new ValueError('Configuration error: paths must be inside the root directory: ' . $root);
    }
}
