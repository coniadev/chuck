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
        $path = realpath($path);

        if ($path === false) {
            throw new RuntimeException('Image does not exist: ' . $path);
        }

        $this->path = $path;
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
                    'File "' . $path . '" is not valid jpg, webp, png or gif image.'
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
            $size->origHeight
        );

        if (!$result) {
            return false;
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

    public function centerSquare(string $path, string $dest, int $size): bool
    {
        $image = self::getImageFromPath($path);

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

        return self::writeImageToPath($thumb, $dest);
    }
}
