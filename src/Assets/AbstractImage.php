<?php

declare(strict_types=1);

namespace Chuck\Assets;

use \RuntimeException;
use Chuck\Util\{Image, Path};


abstract class AbstractImage
{
    protected string $path;
    protected Image $image;
    protected string $relativePath;

    public function __construct(
        protected string $assets,
        protected string $cache,
        string $path
    ) {
        if (Path::isAbsolute($path)) {
            $realPath = realpath($path);
        } else {
            $realPath = realpath($assets . DIRECTORY_SEPARATOR . $path);
        }

        if ($realPath === false) {
            throw new RuntimeException('Image does not exist: ' . $path);
        }

        $this->validatePath($realPath);
        $this->path = $realPath;
        $this->relativePath = $this->getRelativePath();
        $this->image = new Image($realPath);
    }

    abstract protected function getRelativePath(): string;
    abstract protected function validatePath(string $path): void;

    public function path(): string
    {
        return $this->path;
    }

    public function relative(): string
    {
        return $this->relativePath;
    }

    public function delete(): bool
    {
        return unlink($this->path);
    }

    public function get(): Image
    {
        return $this->image;
    }
}
