<?php

declare(strict_types=1);

namespace Chuck\Assets;

use \RuntimeException;
use Chuck\ConfigInterface;
use Chuck\RequestInterface;


class Assets
{

    protected string $assets;
    protected string $cache;

    public function __construct(
        string $assetsPath,
        string $cachePath,
        protected ?RequestInterface $request = null,
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

    public static function fromConfig(ConfigInterface $config): self
    {
        $asset = new  self(
            $config->path('assets.files'),
            $config->path('assets.cache'),
        );

        return $asset;
    }

    public function image(string $path): Image
    {
        return new Image($this->assets, $this->cache, $path);
    }
}
