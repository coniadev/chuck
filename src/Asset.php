<?php

declare(strict_types=1);

namespace Chuck;

use \RuntimeException;
use Chuck\Util\Path;


class Asset
{

    protected string $assetsPath;
    protected string $cachePath;

    public function __construct(
        string $assetsPath,
        string $cachePath
    ) {
        $realAssetsPath = realpath($assetsPath);
        $realCachePath = realpath($cachePath);

        if ($realAssetsPath === false || !is_dir($realAssetsPath)) {
            throw new RuntimeException('Assets directory does not exist: ' . $assetsPath);
        }

        if ($realCachePath === false || !is_dir($realCachePath)) {
            throw new RuntimeException('Assets cache directory does not exist: ' . $cachePath);
        }

        $this->assetsPath = $realAssetsPath;
        $this->cachePath = $realCachePath;
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $asset = new  self(
            $config->path('assets.files'),
            $config->path('assets.cache')
        );

        return $asset;
    }

    public function image(
        string $path,
        int $width = 0,
        int $heigth = 0,
        bool $crop = false
    ): string {
        if (Path::isAbsolute($path)) {
            $realPath = realpath($path);
        } else {
            $realPath = realpath($this->assetsPath . DIRECTORY_SEPARATOR . $path);
        }

        if ($realPath === false) {
            throw new RuntimeException('Image does not exist: ' . $path);
        }

        if (!Path::inside($this->assetsPath, $realPath)) {
            throw new RuntimeException('Image is not inside the assets directory: ' . $path);
        }

        return '';
    }
}
