<?php

declare(strict_types=1);

namespace Chuck;

use \GdImage;
use \RuntimeException;
use Chuck\Util\Image as Tool;


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

    public function get(): GdImage
    {
        $image = Tool::getImageFromPath($this->path);

        return $image;
    }


    public function write(string $path): bool
    {
        return Tool::writeImageToPath($this->get(), $path);
    }

    public function resize(
        int $width = 0,
        int $height = 0,
        bool $crop = false,
    ): GdImage {
        return Tool::resizeImage(
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
        return Tool::writeImageToPath($this->resize($width, $height, $crop), $dest);
    }
}
