<?php

declare(strict_types=1);

namespace Chuck\Assets;

use \RuntimeException;
use Chuck\Util\Path;


class CachedImage extends AbstractImage
{
    protected function validatePath(string $path): void
    {
        if (!Path::inside($this->cache, $path)) {
            throw new RuntimeException('Image is not inside the assets directory: ' . $path);
        }
    }

    protected function getRelativePath(): string
    {
        return trim(substr($this->path, strlen($this->cache)), DIRECTORY_SEPARATOR);
    }
}
