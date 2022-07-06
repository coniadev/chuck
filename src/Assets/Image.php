<?php

declare(strict_types=1);

namespace Conia\Chuck\Assets;

use \RuntimeException;
use Conia\Chuck\Util\Path;


class Image extends AbstractImage
{
    protected function getRelativePath(): string
    {
        return trim(substr($this->path, strlen($this->assets->assets)), DIRECTORY_SEPARATOR);
    }

    protected function validatePath(string $path): void
    {
        if (!Path::inside($this->assets->assets, $path)) {
            throw new RuntimeException('Image is not inside the assets directory: ' . $path);
        }
    }

    protected function cacheFilePath(int $width, int $height, bool $crop): string
    {
        $info = pathinfo($this->relativePath);
        $relativeDir = trim($info['dirname'], '.');
        $seg = explode('.', $info['basename']);
        $cacheDir = $this->assets->cache;

        if (!empty($relativeDir)) {
            $cacheDir .= DIRECTORY_SEPARATOR . $relativeDir;

            // create cache sub directory if it does not exist
            if (!is_dir($cacheDir)) {
                mkdir($cacheDir, 0755, true);
            }
        }

        $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . $seg[0] . '-';

        if ($width > 0) {
            $cacheFile .= ($height === 0) ?
                'w' . (string)$width :
                (string)$width . 'x' . (string)$height;
        } else {
            $cacheFile .= 'h' . (string)$height;
        }

        $ext = implode('.', array_slice($seg, 1));
        $cacheFile .= ($crop ? 'c' : 'b') . (empty($ext) ? '' : '.' . $ext);

        return $cacheFile;
    }

    protected function createCacheFile(string $cacheFile, int $width, int $height, bool $crop): void
    {
        $this->image->thumb($cacheFile, $width, $height, $crop);
    }

    public function resize(int $width = 0, int $height = 0, bool $crop = false): CachedImage
    {
        $cacheFile = $this->cacheFilePath($width, $height, $crop);

        if (is_file($cacheFile)) {
            $fileMtime = filemtime($this->path);
            $cacheMtime = filemtime($cacheFile);

            if ($fileMtime > $cacheMtime) {
                $this->createCacheFile($cacheFile, $width, $height, $crop);
            }
        } else {
            $this->createCacheFile($cacheFile, $width, $height, $crop);
        }

        return new CachedImage($this->assets, $cacheFile);
    }

    public function url(bool $bust = true, ?string $host = null): string
    {
        return $this->getUrl($this->assets->staticRouteAssets, $bust, $host);
    }
}
