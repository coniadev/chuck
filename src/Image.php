<?php

declare(strict_types=1);

namespace Chuck;

use \GdImage;
use \InvalidArgumentException;
use \RuntimeException;


class Image
{
    protected string $path;

    public function __construct(string $path)
    {
        $realPath = realpath($path);

        if ($realPath === false) {
            throw new RuntimeException('Image does not exist: ' . $path);
        }

        $this->path = $realPath;
    }

    public static function getImageFromPath(string $path): GdImage|false
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
                    'File "' . $path . '" is not a valid jpg, webp, png or gif image.'
                );
                break;
        }
    }

    public static function writeImageToPath(GdImage $image, string $path): bool
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


    protected static function resizeImageToValues(
        GdImage $image,
        ImageSize $size,
    ): GdImage {
        $thumb = imagecreatetruecolor($size->newWidth, $size->newHeight);

        // copy source image at a resized size
        $result = imagecopyresampled(
            $thumb,
            $image,
            0,
            0,
            $size->offsetWidth,
            $size->offsetHeight,
            $size->newWidth,
            $size->newHeight,
            $size->origWidth,
            $size->origHeight,
        );

        if (!$result) {
            throw new RuntimeException('Error processing image: could not be resized');
        }

        return $thumb;
    }


    public static function resizeImage(
        GdImage $image,
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): GdImage {
        $size = new ImageSize(
            origWidth: imagesx($image),
            origHeight: imagesy($image),
            newWidth: $width,
            newHeight: $height,
        );

        if ($size->alreadyInBoundingBox()) {
            return $image;
        }

        return self::resizeImageToValues($image, $size->newSize($crop));
    }

    public static function createThumbnail(
        string $path,
        string $dest,
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): bool {
        $image = self::getImageFromPath($path);

        if (!$image) {
            return false;
        }

        return self::writeImageToPath(
            self::resizeImage($image, $width, $height, $crop),
            $dest
        );
    }

    public function get(): GdImage
    {
        $image = self::getImageFromPath($this->path);

        if ($image === false) {
            throw new InvalidArgumentException('Could not read image file');
        }

        return $image;
    }

    public function resize(
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): GdImage {
        return self::resizeImage(
            $this->get(),
            $width,
            $height,
            $crop,
        );
    }

    public function thumb(
        string $dest,
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): bool {
        return self::writeImageToPath($this->resize($width, $height, $crop), $dest);
    }
}
