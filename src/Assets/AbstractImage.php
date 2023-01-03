<?php

declare(strict_types=1);

namespace Conia\Chuck\Assets;

use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Util\{Image, Path};

abstract class AbstractImage
{
    protected string $path;
    protected Image $image;
    protected string $relativePath;

    public function __construct(protected readonly Assets $assets, string $path)
    {
        if (Path::isAbsolute($path)) {
            $realPath = realpath($path);
        } else {
            $realPath = realpath($assets->assets . DIRECTORY_SEPARATOR . $path);
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
    abstract public function url(bool $bust, ?string $host): string;

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

    protected function getUrl(string $staticRouteName, bool $bust, ?string $host): string
    {
        if ($this->assets->router === null) {
            throw new RuntimeException('Assets instance initialized without router');
        }

        $router = $this->assets->router;
        return $router->staticUrl(
            $staticRouteName,
            $this->relativePath,
            $bust,
            $host
        );
    }
}
