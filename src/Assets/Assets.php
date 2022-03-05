<?php

declare(strict_types=1);

namespace Chuck\Assets;

use \RuntimeException;
use Chuck\ConfigInterface;
use Chuck\RequestInterface;


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

    public static function fromConfig(
        ConfigInterface $config,
        ?RequestInterface $request = null,
    ): self {
        $assets = new  self(
            $config->path->get('assets'),
            $config->path->get('cache') . DIRECTORY_SEPARATOR . 'assets',
            $request,
        );

        return $assets;
    }

    public static function fromRequest(RequestInterface $request): self
    {
        $config = $request->getConfig();
        $assets = self::fromConfig($config, $request);

        return $assets;
    }

    public function image(string $path): Image
    {
        return new Image($this, $path);
    }
}
