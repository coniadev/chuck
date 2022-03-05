<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Util\Path as PathUtil;


trait PathTrait
{
    public function insideRoot(string $path): bool
    {
        return PathUtil::inside($this->root, $path);
    }

    protected function preparePath(string $path): string
    {
        $path = PathUtil::realpath($path);

        if (!PathUtil::isAbsolute($path)) {
            $path = $this->root . DIRECTORY_SEPARATOR . $path;
        }

        if (str_starts_with($path, $this->root)) {
            return $path;
        }

        throw new ValueError(
            'Configuration error: paths must be inside the root directory: ' .
                $this->root
        );
    }
}
