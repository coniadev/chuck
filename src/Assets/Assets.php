<?php

declare(strict_types=1);

namespace Conia\Chuck\Assets;

use RuntimeException;
use Conia\Chuck\RequestInterface;

class Assets
{
    public readonly string $assets;
    public readonly string $cache;

    public function __construct(
        string $assetsPath,
        string $cachePath,
        public readonly ?RequestInterface $request = null,
        public readonly string $staticRouteAssets = 'assets',
        public readonly string $staticRouteCache = 'cache',
    ) {
        $realAssetsPath = realpath($assetsPath);
        $realCachePath = realpath($cachePath);

        if ($realAssetsPath === false || !is_dir($realAssetsPath)) {
            throw new RuntimeException('Assets directory does not exist: ' . $assetsPath);
        }

        if ($realCachePath === false || !is_dir($realCachePath)) {
            throw new RuntimeException('Assets cache directory does not exist: ' . $cachePath);
        }

        $this->assets = $realAssetsPath;
        $this->cache = $realCachePath;
    }

    public function image(string $path): Image
    {
        return new Image($this, $path);
    }
}
