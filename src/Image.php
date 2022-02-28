<?php

declare(strict_types=1);

namespace Chuck;

use \GdImage;
use \InvalidArgumentException;
use \RuntimeException;
use Chuck\Util\Path;


class Image
{
    protected string $path;
    protected string $assetsPath;
    protected string $cachePath;

    public function __construct(
        string $path,
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

        if (Path::isAbsolute($path)) {
            $realPath = realpath($path);
        } else {
            $realPath = realpath($realAssetsPath . DIRECTORY_SEPARATOR . $path);
        }

        if ($realPath === false) {
            throw new RuntimeException('Image does not exist: ' . $path);
        }

        if (!Path::inside($realAssetsPath, $realPath)) {
            throw new RuntimeException('Image is not inside the assets directory: ' . $path);
        }

        $this->path = $realPath;
        $this->assetsPath = $realAssetsPath;
        $this->cachePath = $realCachePath;
    }

    public static function fromConfig(string $path, ConfigInterface $config): self
    {
        $image = new  self(
            $path,
            $config->path('assets.files'),
            $config->path('assets.cache')
        );

        return $image;
    }

    public static function getImage(string $path): GdImage|false
    {
        if (!file_exists($path)) {
            throw new \InvalidArgumentException('File "' . $path . '" not found.');
        }

        switch (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
            case 'jfif':
            case 'jpeg':
            case 'jpg':
                return imagecreatefromjpeg($path);
                break;
            case 'png':
                return imagecreatefrompng($path);
                break;
            case 'gif':
                return imagecreatefromgif($path);
                break;
            case 'webp':
                return imagecreatefromwebp($path);
                break;
            default:
                throw new \InvalidArgumentException(
                    'File "' . $path . '" is not valid jpg, webp, png or gif image.'
                );
                break;
        }
    }

    public function get(): GdImage
    {
        $image = self::getImage($this->path);

        if ($image === false) {
            throw new InvalidArgumentException('Could not read image file');
        }

        return $image;
    }

    protected static function writeImage(GdImage $image, string $path): bool
    {
        switch (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
            case 'jfif':
            case 'jpeg':
            case 'jpg':
                return imagejpeg($image, $path);
                break;
            case 'png':
                return imagepng($image, $path);
                break;
            case 'gif':
                return imagegif($image, $path);
                break;
            case 'webp':
                return imagewebp($image, $path);
                break;
            default:
                throw new \InvalidArgumentException('Image with given extension not supported: ' . $path);
        }
    }

    protected static function createThumbnailFromImage(
        GdImage $image,
        string $dest,
        int $newWidth
    ): bool {
        $origWidth = imagesx($image);
        $origHeight = imagesy($image);

        // find the "desired height" of this thumbnail, relative to the desired width
        $newHeight = (int)floor($origHeight * ($newWidth / $origWidth));

        $thumb = imagecreatetruecolor($newWidth, $newHeight);

        // copy source image at a resized size
        $result = imagecopyresampled(
            $thumb,
            $image,
            0,
            0,
            0,
            0,
            $newWidth,
            $newHeight,
            $origWidth,
            $origHeight
        );

        if (!$result) {
            return false;
        }

        return self::writeImage($thumb, $dest);
    }

    public static function createThumbnail(string $path, string $dest, int $newWidth): bool

    {
        $image = self::getImage($path);

        if (!$image) {
            return false;
        }

        return self::createThumbnailFromImage($image, $dest, $newWidth);
    }

    public function thumb(string $dest, int $newWidth): bool
    {
        return $this->createThumbnailFromImage($this->get(), $dest, $newWidth);
    }

    public function centerSquare(string $path, string $dest, int $size): bool
    {
        $image = self::getImage($path);

        if (!$image) {
            return false;
        }

        $x = imagesx($image);
        $y = imagesy($image);

        if ($x > $y) {
            // horizontal rectangle
            $square = $y;              // $square: square side length
            $offsetX = ($x - $y) / 2;  // x offset based on the rectangle
            $offsetY = 0;              // y offset based on the rectangle
        } elseif ($y > $x) {
            // vertical rectangle
            $square = $x;
            $offsetX = 0;
            $offsetY = ($y - $x) / 2;
        } else {
            // it's already a square
            $square = $x;
            $offsetX = $offsetY = 0;
        }

        $thumb = imagecreatetruecolor($size, $size);

        $result = imagecopyresampled(
            $thumb,
            $image,
            0,
            0,
            (int)$offsetX,
            (int)$offsetY,
            $size,
            $size,
            (int)$square,
            (int)$square
        );

        if (!$result) {
            return false;
        }

        return self::writeImage($thumb, $dest);
    }
}
