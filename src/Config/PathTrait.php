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
        $result = PathUtil::realpath($path);

        if (!PathUtil::isAbsolute($result)) {
            $result = realpath($result);
        }

        if ($result) {
            return $result;
        }

        throw new ValueError("Path does not exist: $path");
    }
}
