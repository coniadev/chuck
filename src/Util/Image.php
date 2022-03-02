<?php

declare(strict_types=1);

namespace Chuck\Util;

use \GdImage;
use \RuntimeException;
use Chuck\ImageSize;


class Image
{
    public static function getImageFromPath(string $path): GdImage
    {
        if (!file_exists($path)) {
            throw new \InvalidArgumentException('Image does not exist: ' . $path);
        }

        try {
            switch (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
                case 'jfif':
                case 'jpeg':
                case 'jpg':
                    $result = imagecreatefromjpeg($path);
                    break;
                case 'png':
                    $result = imagecreatefrompng($path);
                    break;
                case 'gif':
                    $result = imagecreatefromgif($path);
                    break;
                case 'webp':
                    $result = imagecreatefromwebp($path);
                    break;
                default:
                    throw new \InvalidArgumentException(
                        'File "' . $path . '" is not a valid jpg, webp, png or gif image.'
                    );
            }
        } catch (\ErrorException) {
            throw new \InvalidArgumentException(
                'File "' . $path . '" is not a valid jpg, webp, png or gif image.'
            );
        }

        return $result;
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

        return self::resizeToBox($image, $size->newSize($crop));
    }

    public static function createResizedImage(
        string $path,
        string $dest,
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): bool {
        $image = self::getImageFromPath($path);

        return self::writeImageToPath(
            self::resizeImage($image, $width, $height, $crop),
            $dest
        );
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

    public static function resizeToBox(
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

        // Haven't found a way to provoke this error
        // @codeCoverageIgnoreStart
        if (!$result) {
            throw new RuntimeException('Error processing image: could not be resized');
        }
        // @codeCoverageIgnoreEnd

        return $thumb;
    }
}
