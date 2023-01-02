<?php

declare(strict_types=1);

namespace Conia\Chuck\Assets;

use Conia\Chuck\Error\RuntimeException;
use Conia\Chuck\Util\Path;

class CachedImage extends AbstractImage
{
    protected function validatePath(string $path): void
    {
        if (!Path::inside($this->assets->cache, $path)) {
            throw new RuntimeException('Image is not inside the cache directory: ' . $path);
        }
    }

    protected function getRelativePath(): string
    {
        return trim(substr($this->path, strlen($this->assets->cache)), DIRECTORY_SEPARATOR);
    }

    public function url(bool $bust = true, ?string $host = null): string
    {
        return $this->getUrl($this->assets->staticRouteCache, $bust, $host);
    }
}
