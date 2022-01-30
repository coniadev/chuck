
<?php

declare(strict_types=1);

namespace Chuck\Util;

class Path
{
    public function __construct(RequestInterface $request = null)
    {
        $this->request = $request;
    }

    public function isInsideRootDir(string $path): bool
    {
        $config = $this->request->config;
        $root = $config->path('root');

        return str_starts_with($path, $root);
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
